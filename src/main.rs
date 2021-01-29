use bloomfilter::Bloom;
use linecount::count_lines;
use serde_json::{json, Value};
use ring::digest;
use std::env;
use std::fs::File;
use std::io::{BufReader, BufRead, BufWriter, Write, Seek, SeekFrom};

fn help_message_and_exit(program_name: &str, status_code: i32) -> String {
    println!("Usage: {} INFILE OUTFILE FALSE_POSITIVE_RATE", program_name);
    std::process::exit(status_code);
}

fn open_file_count_lines(file_name: &str, program_name: &str) -> (usize, File) {
    let f = File::open(file_name);
    if let Err(ref e) = f {
        println!("Error opening INFILE: {}", e);
        help_message_and_exit(program_name, 1);
    }
    let mut f = f.unwrap();
    let lines = count_lines(&f).unwrap();
    f.seek(SeekFrom::Start(0)).unwrap();
    (lines, f)
}

fn create_file(file_name: &str, program_name: &str, file_summary: &str) -> File {
    let of = File::create(file_name);
    if let Err(ref e) = of {
        println!("Error creating {}: {}", e, file_summary);
        help_message_and_exit(program_name, 1);
    };
    of.unwrap()
}

fn create_bloom_filter(infile: File, items_count: usize, fp_rate: f64) -> Bloom<str> {
    let bitmap_size = Bloom::<()>::compute_bitmap_size(items_count, fp_rate);
    println!("Using a bitmap size of {} bytes, appropriate for a false positive rate of {}.", bitmap_size, fp_rate);
    let mut bf = Bloom::<str>::new(bitmap_size, items_count);
    for line in BufReader::new(infile).lines().map(|l| l.unwrap()) {
        bf.set(line.trim());
    }
    bf
}

fn parse_fp_rate(fp_rate_string: &str, program_name: &str) -> f64 {
    let fp_rate: Result<f64, _> = fp_rate_string.parse();
    if let Err(ref e) = fp_rate {
        println!("Error parsing FALSE_POSITIVE_RATE: {}", e);
        help_message_and_exit(program_name, 1);
    }
    fp_rate.unwrap()
}

fn write_outfile(bf: &Bloom<str>, outfile: File) {
    let mut bw = BufWriter::new(outfile);
    bw.write_all(&bf.bitmap()).unwrap();
}

fn write_metadata(json_value: Value, mut metadata_file: File) {
    metadata_file.write_all(json_value.to_string().as_bytes()).unwrap();
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        help_message_and_exit(&args[0], 1);
    }
    let fp_rate = parse_fp_rate(&args[3], &args[0]);
    let outfile = create_file(&args[2], &args[0], "OUTFILE");
    let metadata_file = create_file(&format!("{}.json", &args[2]), &args[0], "metadata file OUTFILE.json");
    let (items_count, infile) = open_file_count_lines(&args[1], &args[0]);

    let bf = create_bloom_filter(infile, items_count, fp_rate);

    println!("Writing bloom filter to file...");
    write_outfile(&bf, outfile);
    let sip_keys = bf.sip_keys();
    let json = json!({
        "sha256sum": hex::encode(digest::digest(&digest::SHA256, &bf.bitmap()).as_ref()),
        "bitmap_bits": bf.number_of_bits(),
        "k_num": bf.number_of_hash_functions(),
        "sip_keys": [
            [sip_keys[0].0.to_string(), sip_keys[0].1.to_string()],
            [sip_keys[1].0.to_string(), sip_keys[1].1.to_string()],
        ]
    });
    write_metadata(json, metadata_file);
}
