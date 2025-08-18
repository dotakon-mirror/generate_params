use halo2_proofs::poly::commitment::Params;
use pasta_curves::pallas::Affine;
use sha3::{Digest, Sha3_256};
use std::{
    fs::File,
    io::{BufWriter, Read},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

const MAX_K: u32 = 15;

static EXPECTED_HASHES: [&str; MAX_K as usize] = [
    "8167c4aa55ef5984fe652334f5406fa45887d8d831b07b5a18d01ef5664c4d0a",
    "0ba030b01c1f53f497f7b9198653d3ee5e0a89e2705a8764168fcd0e6a8026b7",
    "e791ee48f39fe4be345c8908256045c79fd9837025e34b9419a3d99f5d376c9d",
    "a8649bcb59ffd522d3c74ee3dab81dca93164d94abd5808e0e3566489f67abd1",
    "4e8ee64698d8b7f7140a84295d671d7622977a4eb4035e9c4d6e349ee76b347f",
    "108b5930fe07b87ad9ae93cbbf166e848dcfc70be00ca5033fab45ef89f04769",
    "ec8ac1550c92aa9414124963dbaaa1d1cf0bce234a7f5907a437f142adf8bad4",
    "c961a7695392723204da22e38fcf20b9f4a6a462fa9b8c59dc5550ed2e2d5bb8",
    "2d5633506dadba2d25e5e9ccf04944ab3af5dcba9c4af35e7cbe0ee7bb8531b5",
    "d185fc35d5974c1eb50a1fa5681683f865fdcf753650e36e44d2b35132352b61",
    "7e3b6cb34d86bb0f1f9381b8a4cc771f355c141597a27958671721d22d588002",
    "8312a27f6731b8cf09f294ae21ddc170c7dbea916e4f3ae6af82fad49fb66dfb",
    "1461bcd6a8324f4b191a811d4346b30b93fcddf7007e226693176a82121265cd",
    "78c0ad62f1c0c43784095157e997b5ec4fbed7f24983bcb089e7040e6332b008",
    "a84a8311ea02a539fac7d6a6b8e7ea0d6e47d1625ca50a52e1c122869aae417e",
];

fn main() {
    for k in 1..MAX_K {
        let filename = format!("params_k{}.bin", k);
        let expected_hash = EXPECTED_HASHES[(k - 1) as usize];

        if Path::new(&filename).exists() {
            let hash_hex = sha3_file(&filename);
            if hash_hex == expected_hash {
                println!(
                    "{} already exists and hash matches \u{2192} skipping",
                    filename
                );
                continue;
            } else {
                println!(
                    "{} exists but hash mismatch (got {}, expected {}) \u{2192} regenerating",
                    filename, hash_hex, expected_hash
                );
            }
        }

        println!("Generating params for k={}...", k);

        let start_time = Instant::now();
        let running = Arc::new(AtomicBool::new(true));
        let running_clone = running.clone();

        let timer_thread = thread::spawn(move || {
            while running_clone.load(Ordering::Acquire) {
                let total_secs = start_time.elapsed().as_secs();
                let hours = total_secs / 3600;
                let minutes = (total_secs % 3600) / 60;
                let seconds = total_secs % 60;
                print!("\rElapsed time: {:02}:{:02}:{:02}", hours, minutes, seconds);
                use std::io::Write;
                std::io::stdout().flush().unwrap();
                thread::sleep(Duration::from_secs(1));
            }
        });

        let params: Params<Affine> = Params::new(k);

        running.store(false, Ordering::Release);
        timer_thread.join().unwrap();

        let elapsed = start_time.elapsed();
        println!("\rGeneration completed in {:.0?}", elapsed);

        {
            let file = File::create(&filename).expect("unable to create file");
            let mut writer = BufWriter::new(file);
            params
                .write(&mut writer)
                .expect("failed to write params file");
        }

        let hash_hex = sha3_file(&filename);
        println!("  \u{2192} wrote {} (SHA-256: {})", filename, hash_hex);
    }

    println!("All params up to k={} checked/generated.", MAX_K);
}

fn sha3_file(path: &str) -> String {
    let mut f = File::open(path).expect("unable to open file for hashing");
    let mut hasher = Sha3_256::new();
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer).expect("failed to read file");
    hasher.update(&buffer);
    let hash = hasher.finalize();
    hash.iter().map(|b| format!("{:02x}", b)).collect()
}
