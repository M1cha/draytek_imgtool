use byteorder::WriteBytesExt as _;
use clap::Clap as _;
use std::convert::TryInto as _;
use std::io::Seek as _;
use std::io::Write as _;

pub const CRC_32_DRAYTEK: crc::Algorithm<u32> = crc::Algorithm {
    poly: 0x04c11db7,
    init: 0xffffffff,
    refin: true,
    refout: true,
    xorout: 0x00000000,
    check: 0xcbf43926,
    residue: 0xdebb20e3,
};

#[derive(clap::Clap)]
struct Opts {
    /// Path to the LZMA-compressed kernel image
    #[clap(short, long)]
    kernel: std::path::PathBuf,
    /// Path to the LZMA-compressed squashfs
    #[clap(short, long)]
    rootfs: std::path::PathBuf,
    /// Path to the generated draytek image
    #[clap(short, long)]
    output: std::path::PathBuf,

    /// kernel loading address
    #[clap(long, default_value = "0x80002000")]
    kernel_addr: String,
}

struct Crc32DigestWriter<'a, 'b>(&'a mut crc::Digest<'b, u32>);

impl<'a, 'b> Crc32DigestWriter<'a, 'b> {
    pub fn new(digest: &'a mut crc::Digest<'b, u32>) -> Self {
        Self(digest)
    }
}

impl<'a, 'b> std::io::Write for Crc32DigestWriter<'a, 'b> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

trait Hasher {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize>;
}

impl Hasher for md5::Context {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        std::io::Write::write(self, data)
    }
}

struct HashedWriter<'a, H, W> {
    hasher: &'a mut H,
    writer: &'a mut W,
}

impl<'a, H, W> HashedWriter<'a, H, W>
where
    H: Hasher,
    W: std::io::Write,
{
    pub fn new(hasher: &'a mut H, writer: &'a mut W) -> Self {
        Self { hasher, writer }
    }
}

impl<'a, H, W> std::io::Write for HashedWriter<'a, H, W>
where
    H: Hasher,
    W: std::io::Write,
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let len = self.writer.write(buf)?;
        self.hasher.write(&buf[0..len])?;
        Ok(len)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}

fn write_byte_repeat<W: std::io::Write>(
    value: u8,
    len: usize,
    writer: &mut W,
) -> std::io::Result<()> {
    for _ in 0..len {
        writer.write_all(&[value])?;
    }

    Ok(())
}

fn main() -> anyhow::Result<()> {
    let opts: Opts = Opts::parse();

    let header_size = 0x100;

    let mut kernel = std::fs::File::open(&opts.kernel)?;
    let kernel_size = kernel.metadata()?.len();
    let kernel_addr = parse_int::parse::<u32>(&opts.kernel_addr)?;

    let mut rootfs = std::fs::File::open(&opts.rootfs)?;
    let rootfs_size = rootfs.metadata()?.len();

    let image_size = header_size + kernel_size + rootfs_size;
    let mut image_md5_context = md5::Context::new();

    let partitions_crc = crc::Crc::<u32>::new(&CRC_32_DRAYTEK);
    let mut partitions_digest = partitions_crc.digest();
    let mut partitions_digest_writer = Crc32DigestWriter::new(&mut partitions_digest);
    std::io::copy(&mut kernel, &mut partitions_digest_writer)?;
    std::io::copy(&mut rootfs, &mut partitions_digest_writer)?;
    let partitions_crc_value = partitions_digest.finalize();

    // reset input files
    kernel.seek(std::io::SeekFrom::Start(0x0))?;
    rootfs.seek(std::io::SeekFrom::Start(0x0))?;

    let mut out_raw = std::fs::File::create(&opts.output)?;
    let mut out = HashedWriter::new(&mut image_md5_context, &mut out_raw);

    // magic
    out.write_all(b"2RDH")?;
    out.write_u32::<byteorder::BigEndian>(header_size.try_into()?)?;
    out.write_u32::<byteorder::BigEndian>(image_size.try_into()?)?;
    out.write_u32::<byteorder::BigEndian>(partitions_crc_value)?;
    write_byte_repeat(0x00, 64, &mut out)?;

    // image sizes
    out.write_u32::<byteorder::BigEndian>(kernel_size.try_into()?)?;
    out.write_u32::<byteorder::BigEndian>(rootfs_size.try_into()?)?;
    write_byte_repeat(0x00, 36, &mut out)?;

    // kernel address
    out.write_u32::<byteorder::BigEndian>(kernel_addr)?;
    write_byte_repeat(0x00, 8, &mut out)?;

    // unknown
    out.write_u32::<byteorder::BigEndian>(0x01000000)?;
    write_byte_repeat(0x00, 116, &mut out)?;

    // files
    std::io::copy(&mut kernel, &mut out)?;
    std::io::copy(&mut rootfs, &mut out)?;

    let image_md5 = image_md5_context.compute();

    // footer
    write!(&mut out_raw, "DrayTekImageMD5\n{:x}\n", image_md5)?;

    Ok(())
}
