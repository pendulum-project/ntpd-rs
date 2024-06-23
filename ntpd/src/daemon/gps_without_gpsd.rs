use chrono::{NaiveDate, NaiveTime, NaiveDateTime, Utc};
use ntp_proto::NtpTimestamp;
use tracing::info;
use std::io::{self, BufRead, BufReader, Cursor};
use std::time::Duration;
use serialport::{SerialPort};

#[derive(Debug)]
pub struct Gps {
    reader: BufReader<Box<dyn SerialPort>>,
    current_date: Option<String>,
    line: String,
    pub measurement_noise: f64,
}

impl Gps {
    /// Creates a new `GPS` instance.
    ///
    /// This function initializes a new `GPS` struct with a serial port reader,
    /// and sets up the necessary fields for processing GPS data.
    ///
    /// # Arguments
    ///
    /// * `port_name` - The name of the serial port to open (e.g., `/dev/serial0`).
    /// * `baud_rate` - The baud rate for the serial port communication (e.g., 9600).
    /// * `timeout` - The timeout duration for the serial port operations.
    ///
    /// # Returns
    ///
    /// * `io::Result<Self>` - A result containing the new `GPS` instance if successful,
    ///   or an `io::Error` if opening the serial port fails.
    pub fn new(port_name: &str, baud_rate: u32, timeout: Duration, measurement_noise: f64) -> io::Result<Self> {
        let port = serialport::new(port_name, baud_rate)
            .timeout(timeout)
            .open()?;
        let reader = BufReader::new(port);
        Ok(Gps {
            reader,
            current_date: None,
            line: String::new(),
            measurement_noise,
        })
    }

    /// Converts NMEA time and date strings to a Unix timestamp.
    ///
    /// # Arguments
    ///
    /// * `nmea_time` - The NMEA time string.
    /// * `nmea_date` - The NMEA date string.
    ///
    /// # Returns
    ///
    /// * `Option<f64>` - The corresponding Unix timestamp with fractional seconds, or `None` if the conversion fails.
    fn nmea_time_date_to_unix_timestamp(&self, nmea_time: &str, nmea_date: &str) -> Option<(f64, u64, u32)> {
        let (hour, minute, second) = self.parse_nmea_time(nmea_time)?;
        let (day, month, year) = self.parse_nmea_date(nmea_date)?;

        let naive_date = NaiveDate::from_ymd_opt(2000 + year as i32, month, day)?;
        let naive_time = NaiveTime::from_hms_micro_opt(
            hour,
            minute,
            second.trunc() as u32,
            (second.fract() * 1_000_000.0) as u32,
        )?;

        let naive_datetime = NaiveDateTime::new(naive_date, naive_time);
        let timestamp = naive_datetime.and_utc().timestamp() as f64
            + naive_datetime.and_utc().timestamp_subsec_nanos() as f64;

        Some((timestamp, naive_datetime.and_utc().timestamp() as u64, naive_datetime.and_utc().timestamp_subsec_nanos()))
    }

    /// Parses an NMEA time string into hours, minutes, and seconds.
    ///
    /// # Arguments
    ///
    /// * `nmea_time` - The NMEA time string in the format `HHMMSS` or `HHMMSS.SS`.
    ///
    /// # Returns
    ///
    /// * `Option<(u32, u32, f64)>` - A tuple containing hours, minutes and seconds, or `None` if parsing fails.
    fn parse_nmea_time(&self, nmea_time: &str) -> Option<(u32, u32, f64)> {
        if nmea_time.len() < 6 {
            return None;
        }

        let hour: u32 = nmea_time.get(0..2)?.parse().ok()?;
        let minute: u32 = nmea_time.get(2..4)?.parse().ok()?;
        let second: f64 = nmea_time.get(4..).unwrap_or("0").parse().ok()?;

        Some((hour, minute, second))
    }

    /// Parses an NMEA date string into day, month, and year.
    ///
    /// # Arguments
    ///
    /// * `nmea_date` - The NMEA date string in the format `DDMMYY`.
    ///
    /// # Returns
    ///
    /// * `Option<(u32, u32, u32)>` - A tuple containing day, month and year, or `None` if parsing fails.
    fn parse_nmea_date(&self, nmea_date: &str) -> Option<(u32, u32, u32)> {
        if nmea_date.len() < 6 {
            return None;
        }

        let day: u32 = nmea_date.get(0..2)?.parse().ok()?;
        let month: u32 = nmea_date.get(2..4)?.parse().ok()?;
        let year: u32 = nmea_date.get(4..6)?.parse().ok()?;

        Some((day, month, year))
    }

    /// Processes GNRMC fields to update the current date.
    ///
    /// # Arguments
    ///
    /// * `fields` - The GNRMC fields.
    fn process_gnrmc(&mut self, fields: &[&str]) {
        if self.is_valid_gnrmc(fields) {
            if let Some(date) = fields.get(9) {
                self.current_date = Some(date.to_string());
            }
        }
    }

    /// Checks if GNRMC fields are valid.
    ///
    /// # Arguments
    ///
    /// * `fields` - The GNRMC fields.
    ///
    /// # Returns
    ///
    /// * `bool` - `true` if the fields are valid, otherwise `false`.
    fn is_valid_gnrmc(&self, fields: &[&str]) -> bool {
        fields.len() > 9 && fields[2] == "A"
    }

    

    /// Processes GNGGA fields and returns the offset between the GPS time and the system time.
    ///
    /// # Arguments
    ///
    /// * `fields` - The GNGGA fields.
    ///
    /// # Returns
    ///
    /// * `Option<f64>` - The offset in seconds, or `None` if processing fails.
    fn process_gngga(&mut self, fields: &[&str]) -> Option<(f64, NtpTimestamp)> {
        if let Some(time) = fields.get(1) {
            if let Some(date) = &self.current_date {
                if let Some(gps_timestamp) = self.nmea_time_date_to_unix_timestamp(time, date) {
                    let system_time = Utc::now().timestamp() as f64 + Utc::now().timestamp_subsec_micros() as f64 * 1e-6;
                    return Some((system_time - gps_timestamp.0, NtpTimestamp::from_unix_timestamp(gps_timestamp.1, gps_timestamp.2)));

                }
            }
        }
        None
    }

    /// Reads and processes lines from the serial port.
    ///
    /// # Returns
    ///
    /// * `io::Result<Option<f64>>` - The result of reading and processing lines with an optional offset.
    pub async fn current_data(&mut self) -> io::Result<Option<(f64, NtpTimestamp)>> {
        let mut line = String::new();
        match self.reader.read_line(&mut line) {
            Ok(_) => {
                let line = line.trim().to_string(); 
                self.line.clear();
                self.line.push_str(&line); 
                info!("please heree");
                let fields: Vec<&str> = line.split(',').collect(); 
                if line.starts_with("$GNRMC") {
                    info!("or here");
                    self.process_gnrmc(&fields);
                } else if line.starts_with("$GNGGA") {
                    info!("no we here");
                    return Ok(self.process_gngga(&fields));
                }
                Ok(None)
            },
            Err(e) => {
                eprintln!("Error reading from serial port: {}", e);
                Err(e)
            }
        }
    }
}

// fn open_serial_port(port_name: &str, baud_rate: u32, timeout: Duration) -> io::Result<Box<dyn SerialPort>> {
//     serialport::new(port_name, baud_rate)
//         .timeout(timeout)
//         .open()
//         .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
// }

// #[tokio::main]
// async fn main() -> io::Result<()> {
//     let port_name = "/dev/serial0";
//     let baud_rate = 9600;
//     let timeout = Duration::from_secs(10);

//     match GPS::new(port_name, baud_rate, timeout) {
//         Ok(mut gps) => {
//             loop {
//                 match gps.current_data().await {
//                     Ok(Some(offset)) => println!("Offset between GPS time and system time: {:.6} seconds", offset),
//                     Ok(None) => continue,
//                     Err(e) => {
//                         eprintln!("Error processing GPS data: {}", e);
//                         break;
//                     }
//                 }
//             }
//         }
//         Err(e) => eprintln!("Failed to initialize GPS: {}", e),
//     }

//     Ok(())
// }


// #[cfg(test)]
// mod tests {
//     use super::*;
//     use std::io::{self, BufRead, BufReader, Cursor};
//     use std::time::Duration;
//     use serialport::SerialPort;

//     #[test]
//     fn test_parse_nmea_time() {
//         let result = parse_nmea_time("123519");
//         assert_eq!(result, Some((12, 35, 19.0)));

//         let result = parse_nmea_time("123519.00");
//         assert_eq!(result, Some((12, 35, 19.00)));

//         let result = parse_nmea_time("1234");
//         assert_eq!(result, None);

//         let result = parse_nmea_time("ab3519");
//         assert_eq!(result, None);

//         let result = parse_nmea_time("12ab19");
//         assert_eq!(result, None);

//         let result = parse_nmea_time("1235ab");
//         assert_eq!(result, None);

//         let result = parse_nmea_time("000000");
//         assert_eq!(result, Some((0, 0, 0.0)));
//     }

//     #[test]
//     fn test_parse_nmea_date() {
//         let result = parse_nmea_date("230394");
//         assert_eq!(result, Some((23, 3, 94)));

//         let result = parse_nmea_date("2303");
//         assert_eq!(result, None);

//         let result = parse_nmea_date("ab0394");
//         assert_eq!(result, None);

//         let result = parse_nmea_date("23ab94");
//         assert_eq!(result, None);

//         let result = parse_nmea_date("2303ab");
//         assert_eq!(result, None);

//         let result = parse_nmea_date("010100");
//         assert_eq!(result, Some((1, 1, 0)));
//     }

//     #[test]
//     fn test_nmea_time_date_to_unix_timestamp() {
//         let result = nmea_time_date_to_unix_timestamp("123519.00", "250320");
//         assert_eq!(result, Some(1585139719.00));

//         let result = nmea_time_date_to_unix_timestamp("1234", "250320");
//         assert_eq!(result, None);

//         let result = nmea_time_date_to_unix_timestamp("123519.00", "2503");
//         assert_eq!(result, None);

//         let result = nmea_time_date_to_unix_timestamp("12ab19.00", "250320");
//         assert_eq!(result, None);

//         let result = nmea_time_date_to_unix_timestamp("123519.00", "25ab20");
//         assert_eq!(result, None);

//         let result = nmea_time_date_to_unix_timestamp("000000.00", "010100");
//         assert_eq!(result, Some(946684800.00)); 
//     }

//     #[test]
//     fn test_process_gnrmc_with_valid_data() {
//         let mut current_date = None;
//         let fields = vec!["GNRMC", "123519.00", "A", "4807.038", "N", "01131.000", "E", "022.4", "084.4", "250320"];
//         process_gnrmc(&fields, &mut current_date);
//         assert_eq!(current_date, Some("250320".to_string()));
//     }

//     #[test]
//     fn test_process_gnrmc_with_invalid_data() {
//         let mut current_date = None;
//         let fields = vec!["GNRMC", "123519.00", "V", "4807.038", "N", "01131.000", "E", "022.4", "084.4", "250320"];
//         process_gnrmc(&fields, &mut current_date);
//         assert_eq!(current_date, None);
//     }

//     #[test]
//     fn test_process_gnrmc_with_insufficient_fields() {
//         let mut current_date = None;
//         let fields = vec!["GNRMC", "123519.00", "A"];
//         process_gnrmc(&fields, &mut current_date);
//         assert_eq!(current_date, None);
//     }

//     #[test]
//     fn test_process_gnrmc_updates_current_date() {
//         let mut current_date = Some("240320".to_string());
//         let fields = vec!["GNRMC", "123519.00", "A", "4807.038", "N", "01131.000", "E", "022.4", "084.4", "250320"];
//         process_gnrmc(&fields, &mut current_date);
//         assert_eq!(current_date, Some("250320".to_string()));
//     }

//     #[test]
//     fn test_is_valid_gnrmc_with_valid_data() {
//         let fields = vec!["GNRMC", "123519.00", "A", "4807.038", "N", "01131.000", "E", "022.4", "084.4", "250320"];
//         assert!(is_valid_gnrmc(&fields));
//     }

//     #[test]
//     fn test_is_valid_gnrmc_with_invalid_status() {
//         let fields = vec!["GNRMC", "123519.00", "V", "4807.038", "N", "01131.000", "E", "022.4", "084.4", "250320"];
//         assert!(!is_valid_gnrmc(&fields));
//     }

//     #[test]
//     fn test_is_valid_gnrmc_with_insufficient_fields() {
//         let fields = vec!["GNRMC", "123519.00", "A"];
//         assert!(!is_valid_gnrmc(&fields));
//     }
// }

// Mock of SerialPort, testing
struct MockSerialPort {
    data: Cursor<String>,
}

impl io::Read for MockSerialPort {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.data.read(buf)
    }
}

impl io::Write for MockSerialPort {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl SerialPort for MockSerialPort {
    fn name(&self) -> Option<String> {
        Some("MockSerialPort".to_string())
    }

    fn baud_rate(&self) -> serialport::Result<u32> {
        Ok(9600)
    }

    fn data_bits(&self) -> serialport::Result<serialport::DataBits> {
        Ok(serialport::DataBits::Eight)
    }

    fn flow_control(&self) -> serialport::Result<serialport::FlowControl> {
        Ok(serialport::FlowControl::None)
    }

    fn parity(&self) -> serialport::Result<serialport::Parity> {
        Ok(serialport::Parity::None)
    }

    fn stop_bits(&self) -> serialport::Result<serialport::StopBits> {
        Ok(serialport::StopBits::One)
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(1)
    }

    fn set_baud_rate(&mut self, _: u32) -> serialport::Result<()> {
        Ok(())
    }

    fn set_data_bits(&mut self, _: serialport::DataBits) -> serialport::Result<()> {
        Ok(())
    }

    fn set_flow_control(&mut self, _: serialport::FlowControl) -> serialport::Result<()> {
        Ok(())
    }

    fn set_parity(&mut self, _: serialport::Parity) -> serialport::Result<()> {
        Ok(())
    }

    fn set_stop_bits(&mut self, _: serialport::StopBits) -> serialport::Result<()> {
        Ok(())
    }

    fn set_timeout(&mut self, _: Duration) -> serialport::Result<()> {
        Ok(())
    }

    fn write_request_to_send(&mut self, _: bool) -> serialport::Result<()> {
        Ok(())
    }

    fn write_data_terminal_ready(&mut self, _: bool) -> serialport::Result<()> {
        Ok(())
    }

    fn read_clear_to_send(&mut self) -> serialport::Result<bool> {
        Ok(true)
    }

    fn read_data_set_ready(&mut self) -> serialport::Result<bool> {
        Ok(true)
    }

    fn read_ring_indicator(&mut self) -> serialport::Result<bool> {
        Ok(false)
    }

    fn read_carrier_detect(&mut self) -> serialport::Result<bool> {
        Ok(true)
    }

    fn bytes_to_read(&self) -> serialport::Result<u32> {
        Ok(self.data.get_ref().len() as u32)
    }

    fn bytes_to_write(&self) -> serialport::Result<u32> {
        Ok(0)
    }

    fn clear(&self, _: serialport::ClearBuffer) -> serialport::Result<()> {
        Ok(())
    }

    fn try_clone(&self) -> serialport::Result<Box<dyn SerialPort>> {
        Ok(Box::new(MockSerialPort {
            data: self.data.clone(),
        }))
    }

    fn set_break(&self) -> serialport::Result<()> {
        Ok(())
    }

    fn clear_break(&self) -> serialport::Result<()> {
        Ok(())
    }
}

// Some MOCK testing
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{NaiveDate, NaiveTime, NaiveDateTime};
    use std::io::Cursor;

    //mock the gps data
    fn create_gps_with_mock_reader(data: &str) -> Gps {
        let cursor = Cursor::new(data.to_string());
        let reader = BufReader::new(Box::new(MockSerialPort { data: cursor }) as Box<dyn SerialPort>);
        Gps {
            reader,
            current_date: None,
            line: String::new(),
            measurement_noise: 1.0,
        }
    }

    //test if it parses the time from nmea format
    #[test]
    fn test_parse_nmea_time() {
        let gps = create_gps_with_mock_reader("");
        let result = gps.parse_nmea_time("134510");
        assert_eq!(result, Some((13, 45, 10.0)));

        let result = gps.parse_nmea_time("134510.00");
        assert_eq!(result, Some((13, 45, 10.00)));

        let result = gps.parse_nmea_time("1345");
        assert_eq!(result, None);

        let result = gps.parse_nmea_time("ab4510");
        assert_eq!(result, None);

        let result = gps.parse_nmea_time("13ab10");
        assert_eq!(result, None);

        let result = gps.parse_nmea_time("1345ab");
        assert_eq!(result, None);

        let result = gps.parse_nmea_time("000000");
        assert_eq!(result, Some((0, 0, 0.0)));
    }

    //test if it parses the date from nmea format
    #[test]
    fn test_parse_nmea_date() {
        let gps = create_gps_with_mock_reader("");
        let result = gps.parse_nmea_date("220334");
        assert_eq!(result, Some((22, 3, 34)));

        let result = gps.parse_nmea_date("2203");
        assert_eq!(result, None);

        let result = gps.parse_nmea_date("ab0334");
        assert_eq!(result, None);

        let result = gps.parse_nmea_date("22ab34");
        assert_eq!(result, None);

        let result = gps.parse_nmea_date("2203ab");
        assert_eq!(result, None);

        let result = gps.parse_nmea_date("010100");
        assert_eq!(result, Some((1, 1, 0)));
    }

    //test if it parses the nmea format to unix time
    #[test]
    fn test_nmea_time_date_to_unix_timestamp() {
        let gps = create_gps_with_mock_reader("");
        let result = gps.nmea_time_date_to_unix_timestamp("134510.00", "250320");
        let expected = NaiveDateTime::new(
            NaiveDate::from_ymd(2020, 3, 25),
            NaiveTime::from_hms_micro(13, 45, 10, 0),
        );
        assert_eq!(
            result,
            Some((
                expected.timestamp() as f64 + expected.timestamp_subsec_nanos() as f64 * 1e-9,
                expected.timestamp() as u64,
                expected.timestamp_subsec_nanos()
            ))
        );

        let result = gps.nmea_time_date_to_unix_timestamp("1234", "250320");
        assert_eq!(result, None);

        let result = gps.nmea_time_date_to_unix_timestamp("123519.00", "2503");
        assert_eq!(result, None);

        let result = gps.nmea_time_date_to_unix_timestamp("12ab19.00", "250320");
        assert_eq!(result, None);

        let result = gps.nmea_time_date_to_unix_timestamp("123519.00", "25ab20");
        assert_eq!(result, None);

        let result = gps.nmea_time_date_to_unix_timestamp("000000.00", "010100");
        let expected = NaiveDateTime::new(
            NaiveDate::from_ymd(2000, 1, 1),
            NaiveTime::from_hms_micro(0, 0, 0, 0),
        );
        assert_eq!(
            result,
            Some((
                expected.timestamp() as f64 + expected.timestamp_subsec_nanos() as f64 * 1e-9,
                expected.timestamp() as u64,
                expected.timestamp_subsec_nanos()
            ))
        );
    }

    // test if it parses gnrmc data packet
    #[test]
    fn test_process_gnrmc_with_valid_data() {
        let mut gps = create_gps_with_mock_reader("");
        let fields = vec!["$GNRMC", "123519.00", "A", "4807.038", "N", "01131.000", "E", "022.4", "084.4", "250320"];
        gps.process_gnrmc(&fields);
        assert_eq!(gps.current_date, Some("250320".to_string()));
    }

    // test if it parses gnrmc data packet if its an invalid format
    #[test]
    fn test_process_gnrmc_with_invalid_data() {
        let mut gps = create_gps_with_mock_reader("");
        let fields = vec!["$GNRMC", "123519.00", "V", "4807.038", "N", "01131.000", "E", "022.4", "084.4", "250320"];
        gps.process_gnrmc(&fields);
        assert_eq!(gps.current_date, None);
    }

    // test if it parses gnrmc data packet if there is insufficient data fields
    #[test]
    fn test_process_gnrmc_with_insufficient_fields() {
        let mut gps = create_gps_with_mock_reader("");
        let fields = vec!["$GNRMC", "123519.00", "A"];
        gps.process_gnrmc(&fields);
        assert_eq!(gps.current_date, None);
    }

    // test if it parses gnrmc data packet with only date field
    #[test]
    fn test_process_gnrmc_updates_current_date() {
        let mut gps = create_gps_with_mock_reader("");
        gps.current_date = Some("240320".to_string());
        let fields = vec!["$GNRMC", "123519.00", "A", "4807.038", "N", "01131.000", "E", "022.4", "084.4", "250320"];
        gps.process_gnrmc(&fields);
        assert_eq!(gps.current_date, Some("250320".to_string()));
    }

    // test if it parses gnrmc data packet with valid data
    #[test]
    fn test_is_valid_gnrmc_with_valid_data() {
        let gps = create_gps_with_mock_reader("");
        let fields = vec!["$GNRMC", "123519.00", "A", "4807.038", "N", "01131.000", "E", "022.4", "084.4", "250320"];
        assert!(gps.is_valid_gnrmc(&fields));
    }

    // test if it parses gnrmc data packet with invalid status
    #[test]
    fn test_is_valid_gnrmc_with_invalid_status() {
        let gps = create_gps_with_mock_reader("");
        let fields = vec!["$GNRMC", "123519.00", "V", "4807.038", "N", "01131.000", "E", "022.4", "084.4", "250320"];
        assert!(!gps.is_valid_gnrmc(&fields));
    }

    // test if it parses gnrmc data packet with insufficient fields
    #[test]
    fn test_is_valid_gnrmc_with_insufficient_fields() {
        let gps = create_gps_with_mock_reader("");
        let fields = vec!["$GNRMC", "123519.00", "A"];
        assert!(!gps.is_valid_gnrmc(&fields));
    }

    // test if it parses gnrmc data packet with valid data
    #[tokio::test]
    async fn test_current_data_with_gngga() {
        let mut gps = create_gps_with_mock_reader("$GNGGA,123519.00,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47\n");
        gps.current_date = Some("250320".to_string());
        let result = gps.current_data().await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    // test if it parses gnrmc data packet with valid data
    #[tokio::test]
    async fn test_current_data_with_gnrmc() {
        let mut gps = create_gps_with_mock_reader("$GNRMC,123519.00,A,4807.038,N,01131.000,E,022.4,084.4,250320,,*1F\n");
        let result = gps.current_data().await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
        assert_eq!(gps.current_date, Some("250320".to_string()));
    }
}