#![allow(unstable_name_collisions)]

use anyhow::Context as _;
use byteorder::ReadBytesExt as _;
use byteorder::WriteBytesExt as _;
use clap::Parser as _;
use itertools::Itertools as _;
use std::convert::TryInto as _;
use std::io::Read as _;
use std::io::Seek as _;
use std::io::Write as _;

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;

pub const CRC_32_DRAYTEK: crc::Algorithm<u32> = crc::Algorithm {
    width: 32,
    poly: 0x04c11db7,
    init: 0xffffffff,
    refin: true,
    refout: true,
    xorout: 0x00000000,
    check: 0xcbf43926,
    residue: 0xdebb20e3,
};

#[derive(clap::Parser)]
struct DecryptCommand {
    /// Path to encrypted image
    #[clap(short, long)]
    input: std::path::PathBuf,
    /// Path to decrypted image
    #[clap(short, long)]
    output: std::path::PathBuf,
}

#[derive(clap::Parser)]
struct PackCommand {
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

#[derive(clap::Parser)]
struct UnpackCommand {
    /// Path to draytek image
    #[clap(short, long)]
    image: std::path::PathBuf,
    /// Path to a directory where all files will be placed
    #[clap(short, long)]
    output: std::path::PathBuf,
}

#[derive(clap::Subcommand)]
enum Commands {
    Decrypt(DecryptCommand),
    Pack(PackCommand),
    Unpack(UnpackCommand),
}

#[derive(clap::Parser)]
struct Opts {
    #[command(subcommand)]
    command: Commands,
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

struct HashedReader<'a, H, R> {
    hasher: &'a mut H,
    reader: &'a mut R,
}

impl<'a, H, R> HashedReader<'a, H, R>
where
    H: Hasher,
    R: std::io::Read,
{
    pub fn new(hasher: &'a mut H, reader: &'a mut R) -> Self {
        Self { hasher, reader }
    }
}

impl<'a, H, R> std::io::Read for HashedReader<'a, H, R>
where
    H: Hasher,
    R: std::io::Read,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let len = self.reader.read(buf)?;
        self.hasher.write(&buf[0..len])?;
        Ok(len)
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

fn decrypt(opts: DecryptCommand) -> anyhow::Result<()> {
    let mut image_data = vec![];
    let image_data = {
        let mut image = std::fs::File::open(&opts.input)?;
        let num_read = image.read_to_end(&mut image_data)?;
        &mut image_data[..num_read]
    };

    let is_encrypted = u32::from_be_bytes(image_data[0x8C..0x90].try_into().unwrap());
    if is_encrypted != 0x01000000 {
        anyhow::bail!("The file is not encrypted");
    }
    let nonce_prefix = &image_data[0x90..0x94];

    let mut key = [0; 32];
    key.iter_mut()
        .enumerate()
        .for_each(|(index, v)| *v = index.try_into().unwrap());
    b"Vigor167"
        .iter()
        .enumerate()
        .for_each(|(index, char)| key[index] = *char);

    let mut nonce = [0; 12];
    nonce
        .iter_mut()
        .enumerate()
        .for_each(|(index, v)| *v = index.try_into().unwrap());
    nonce[..4].copy_from_slice(nonce_prefix);

    let mut cipher = ChaCha20::new(&key.into(), &nonce.into());
    cipher.apply_keystream(&mut image_data[0x100..]);

    image_data[0x8C] = 0x00;
    image_data[0x90..0x94].copy_from_slice(&0u32.to_be_bytes());

    let mut plaintext_file = std::fs::File::create(&opts.output)?;
    plaintext_file.write_all(image_data)?;

    Ok(())
}

fn pack(opts: PackCommand) -> anyhow::Result<()> {
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

fn expect_zeros<R: std::io::Read>(reader: &mut R, num: usize) -> anyhow::Result<()> {
    let mut zeros = vec![0; num];
    reader.read_exact(&mut zeros)?;
    if zeros != vec![0; num] {
        let hexdump_str: String = hexdump::hexdump_iter(&zeros)
            .map(|line| line.to_string())
            .intersperse("\n".to_string())
            .collect();
        anyhow::bail!("unexpected nonzero data: \n{hexdump_str}");
    }

    Ok(())
}

fn unpack(opts: UnpackCommand) -> anyhow::Result<()> {
    let mut image_raw = std::fs::File::open(&opts.image)?;
    let mut image_md5_context = md5::Context::new();
    let mut image = HashedReader::new(&mut image_md5_context, &mut image_raw);

    let mut magic = [0; 4];
    image.read_exact(&mut magic)?;
    if &magic != b"2RDH" {
        anyhow::bail!("unsupported magic");
    }

    let header_size = image.read_u32::<byteorder::BigEndian>()?;
    tracing::debug!("header size: {header_size}");

    let image_size = image.read_u32::<byteorder::BigEndian>()?;
    tracing::debug!("image size: {image_size}");

    let partitions_crc_value = image.read_u32::<byteorder::BigEndian>()?;
    tracing::debug!("partitions CRC: {partitions_crc_value:08X}");

    expect_zeros(&mut image, 64).context("unsupported header(1) fields")?;

    let kernel_size = image.read_u32::<byteorder::BigEndian>()?;
    tracing::debug!("kernel size: {kernel_size}");

    let rootfs_size = image.read_u32::<byteorder::BigEndian>()?;
    tracing::debug!("rootfs size: {rootfs_size}");

    expect_zeros(&mut image, 36).context("unsupported header(2) fields")?;

    let kernel_address = image.read_u32::<byteorder::BigEndian>()?;
    tracing::debug!("kernel address: {kernel_address:08X}");
    expect_zeros(&mut image, 8)?;

    let unknown = image.read_u32::<byteorder::BigEndian>()?;
    if unknown != 0x01000000 {
        anyhow::bail!("unsupported value for `unknown`");
    }

    let encrypted = image.read_u32::<byteorder::BigEndian>()?;
    let nonce_prefix = image.read_u32::<byteorder::BigEndian>()?;

    if encrypted != 0 || nonce_prefix != 0x00000000 {
        anyhow::bail!("you need to decrypt the image first");
    }

    expect_zeros(&mut image, 108).context("unsupported trailing header data")?;

    let mut kernel = vec![0; kernel_size.try_into().unwrap()];
    image.read_exact(&mut kernel)?;

    let mut rootfs = vec![0; rootfs_size.try_into().unwrap()];
    image.read_exact(&mut rootfs)?;

    {
        let mut kernel_file = std::fs::File::create(opts.output.join("kernel"))?;
        kernel_file.write_all(&kernel)?;
    }

    {
        let mut rootfs_file = std::fs::File::create(opts.output.join("rootfs"))?;
        rootfs_file.write_all(&rootfs)?;
    }

    let partitions_crc = crc::Crc::<u32>::new(&CRC_32_DRAYTEK);
    let mut partitions_digest = partitions_crc.digest();
    partitions_digest.update(&kernel);
    partitions_digest.update(&rootfs);
    let partitions_crc_value_calculated = partitions_digest.finalize();
    if partitions_crc_value_calculated != partitions_crc_value {
        anyhow::bail!(
            "unexpected calculated partitions CRC: {partitions_crc_value_calculated:02X}"
        );
    }

    let mut image = image_raw;
    let md5_calculated = image_md5_context.compute();

    let mut md5_header = [0; 16];
    image.read_exact(&mut md5_header)?;
    if &md5_header != b"DrayTekImageMD5\n" {
        anyhow::bail!("unexpected MD5 header");
    }

    let mut md5_str = [0; 32];
    image.read_exact(&mut md5_str)?;

    let mut md5 = [0u8; 16];
    hex::decode_to_slice(md5_str, &mut md5)?;
    if md5 != *md5_calculated {
        anyhow::bail!("MD5 mismatch");
    }

    if image.read_u8()? != b'\n' {
        anyhow::bail!("wrong MD5 footer");
    }

    let mut rest = vec![];
    image.read_to_end(&mut rest)?;
    if !rest.is_empty() {
        let hexdump_str: String = hexdump::hexdump_iter(&rest)
            .map(|line| line.to_string())
            .intersperse("\n".to_string())
            .collect();
        anyhow::bail!("unexpected trailing data: \n{hexdump_str}");
    }

    Ok(())
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let opts: Opts = Opts::parse();
    match opts.command {
        Commands::Decrypt(opts) => decrypt(opts),
        Commands::Pack(opts) => pack(opts),
        Commands::Unpack(opts) => unpack(opts),
    }
}
