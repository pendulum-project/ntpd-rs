use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::io::{self, BufRead, BufReader, Write, Read}; 
use std::net::TcpStream;
use std::time::Duration as StdDuration;
use std::thread; 

#[derive(Debug, Deserialize)]
#[serde(tag = "class")]
enum GpsdResponse {
    TPV {
        time: Option<String>,
        ept: Option<f64>,
    },
    PPS {
        real_sec: Option<i64>,
        real_nsec: Option<i64>,
    },
    VERSION {},
    DEVICES {},
    WATCH {},
    SKY {},
    GST {},
}

fn connect_to_gpsd() -> io::Result<TcpStream> {
    let gpsd_address = "127.0.0.1:2947"; // Default GPSD address
    let stream = TcpStream::connect(gpsd_address)?;
    stream.set_nonblocking(true)?;
    Ok(stream)
}

fn send_gpsd_command(stream: &mut TcpStream, command: &str) -> io::Result<()> {
    stream.write_all(command.as_bytes())?;
    stream.flush()?;
    Ok(())
}

fn process_response(line: &str) {
    match serde_json::from_str::<GpsdResponse>(line) {
        Ok(response) => match response {
            GpsdResponse::TPV { time, ept: _ } => {
                if let Some(timestamp) = time {
                    match DateTime::parse_from_rfc3339(&timestamp) {
                        Ok(datetime) => {
                            let datetime = datetime.with_timezone(&Utc);
                            println!("Timestamp: {}", datetime);

                            let now = Utc::now();
                            let duration = now.signed_duration_since(datetime);
                            println!("Duration since GPS timestamp: {}", duration);

                            let offset = duration.num_nanoseconds().unwrap_or(0) as f64 / 1e9;
                            println!("Offset: {} seconds", offset);

                            let instant = now;
                            println!("Instant: {}", instant);
                        }
                        Err(e) => eprintln!("Failed to parse timestamp: {}", e),
                    }
                }
            }
            GpsdResponse::PPS { real_sec, real_nsec } => {
                if let (Some(real_sec), Some(real_nsec)) = (real_sec, real_nsec) {
                    let pps_time = Utc.timestamp(real_sec, real_nsec as u32); 
                    println!("PPS time: {}", pps_time);

                    let now = Utc::now();
                    let duration = now.signed_duration_since(pps_time);
                    println!("Duration since PPS: {}", duration);

                    let offset = duration.num_nanoseconds().unwrap_or(0) as f64 / 1e9;
                    println!("Offset: {} seconds", offset);

                    let instant = now;
                    println!("Instant: {}", instant);
                }
            }
            GpsdResponse::VERSION {} => {
                println!("Received VERSION response, ignoring...");
            }
            GpsdResponse::DEVICES {} => {
                println!("Received DEVICES response, ignoring...");
            }
            GpsdResponse::WATCH {} => {
                println!("Received WATCH response, ignoring...");
            }
            GpsdResponse::SKY {} => {
                println!("Received SKY response, ignoring...");
            }
            GpsdResponse::GST {} => {
                println!("Received GST response, ignoring...");
            }
        },
        Err(e) => eprintln!("Failed to parse JSON: {}", e),
    }
}

fn read_and_process_lines(reader: &mut BufReader<TcpStream>) -> io::Result<()> {
    let mut line = String::new();
    let mut buffer = [0; 512];
    loop {
        match reader.get_mut().read(&mut buffer) {
            Ok(n) if n > 0 => {
                line.clear();
                line.push_str(&String::from_utf8_lossy(&buffer[..n]));
                process_response(&line);
            }
            Ok(_) => {}
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(StdDuration::from_millis(10)); 
            }
            Err(e) => {
                eprintln!("Error reading from GPSD: {}", e);
                break;
            }
        }
    }
    Ok(())
}

fn main() -> io::Result<()> {
    let mut stream = connect_to_gpsd()?;
    let mut reader = BufReader::new(stream.try_clone()?);

    send_gpsd_command(&mut stream, "?WATCH={\"enable\":true,\"json\":true}\n")?;

    if let Err(e) = read_and_process_lines(&mut reader) {
        eprintln!("Error processing lines from GPSD: {}", e);
    }

    Ok(())
}