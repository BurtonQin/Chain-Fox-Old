use super::banner::BANNER;
use anyhow::{anyhow, Error, Result};
use serde::{Deserialize, Serialize};
use std::{
  fs,
  io::{stdin, Write},
  path::{Path, PathBuf},
};
use secret_structs::secret as sec; 
use secret_structs::lattice as lat; 
use secret_macros::{InvisibleSideEffectFreeDerive, secret_block};

const DEFAULT_PORT: u16 = 8888;
const FILE_NAME: &str = "client.yml";
const CONFIG_DIR: &str = ".config";
const APP_CONFIG_DIR: &str = "spotify-tui";
const TOKEN_CACHE_FILE: &str = ".spotify_token_cache.json";

#[derive(Default, Clone, Debug, PartialEq, Serialize, Deserialize, InvisibleSideEffectFreeDerive)]
pub struct SerializableClientConfig {
  pub client_id: String,
  pub client_secret: String,
  pub device_id: Option<String>,
  pub port: Option<u16>,
}

pub struct ConfigPaths {
  pub config_file_path: PathBuf,
  pub token_cache_path: PathBuf,
}

#[derive(Default, Clone/*, Debug, PartialEq, Serialize, Deserialize*/)]
pub struct ClientConfig {
  pub client_id: String,
  pub client_secret: sec::Secret<String, lat::Label_A>,
  pub device_id: Option<String>,
  // FIXME: port should be defined in `user_config` not in here
  pub port: Option<u16>,
}

impl ClientConfig {
  pub fn new() -> ClientConfig {
    let cli_sec: sec::Secret<String, lat::Label_A> = secret_block!(lat::Label_A { wrap_secret(std::string::String::from("")) });
    ClientConfig {
      client_id: "".to_string(),
      client_secret: cli_sec,
      device_id: None,
      port: None,
    }
  }

  pub fn get_redirect_uri(&self) -> String {
    format!("http://localhost:{}/callback", self.get_port())
  }

  pub fn get_port(&self) -> u16 {
    self.port.unwrap_or(DEFAULT_PORT)
  }

  pub fn get_or_build_paths(&self) -> Result<ConfigPaths> {
    match dirs::home_dir() {
      Some(home) => {
        let path = Path::new(&home);
        let home_config_dir = path.join(CONFIG_DIR);
        let app_config_dir = home_config_dir.join(APP_CONFIG_DIR);

        if !home_config_dir.exists() {
          fs::create_dir(&home_config_dir)?;
        }

        if !app_config_dir.exists() {
          fs::create_dir(&app_config_dir)?;
        }

        let config_file_path = &app_config_dir.join(FILE_NAME);
        let token_cache_path = &app_config_dir.join(TOKEN_CACHE_FILE);

        let paths = ConfigPaths {
          config_file_path: config_file_path.to_path_buf(),
          token_cache_path: token_cache_path.to_path_buf(),
        };

        Ok(paths)
      }
      None => Err(anyhow!("No $HOME directory found for client config")),
    }
  }

  pub fn set_device_id(&mut self, device_id: String) -> Result<()> {
    let paths = self.get_or_build_paths()?;
    let fs_str = fs::read_to_string(&paths.config_file_path)?;
    let config_string: sec::Secret<String, lat::Label_A> = secret_structs::secret_block!(lat::Label_A {wrap_secret(fs_str)});
    let serde_yaml_str = serde_yaml::from_str(config_string.declassify_ref())?;
    let mut serializable_config: sec::Secret<SerializableClientConfig, lat::Label_A> = 
      secret_block!(lat::Label_A { wrap_secret(serde_yaml_str) });
    self.device_id = Some(device_id.clone());
    secret_structs::secret_block_no_return!(lat::Label_A {
      let u_config = unwrap_secret_mut_ref(&mut serializable_config);
      u_config.device_id = std::option::Option::Some(device_id);
    });

    let mut config_file = fs::File::create(&paths.config_file_path)?;
    let serde_yaml_str = serde_yaml::to_string(serializable_config.declassify_ref())?;
    let new_config: sec::Secret<String, lat::Label_A> = secret_structs::secret_block!(lat::Label_A {wrap_secret(serde_yaml_str)});
    write!(config_file, "{}", new_config.declassify_ref())?;
    Ok(())
  }

  pub fn load_config(&mut self) -> Result<std::time::Instant> { // Returns start time (or 0 if config file doesn't exist)
    let paths = self.get_or_build_paths()?;
    if paths.config_file_path.exists() {
      let config_string = fs::read_to_string(&paths.config_file_path)?;

      //let mut unused = 0u32;
      //let start = unsafe { core::arch::x86_64::__rdtscp(&mut unused)};
      let start = std::time::Instant::now();

      let config_string: sec::Secret<String, lat::Label_A> = secret_block!(lat::Label_A { wrap_secret(config_string)});
      let serde_yaml_str = serde_yaml::from_str(config_string.declassify_ref())?;
      let serializable_config_yml: sec::Secret<SerializableClientConfig, lat::Label_A> = 
        secret_block!(lat::Label_A { wrap_secret(serde_yaml_str) });

      let decomposed_secret: (sec::Secret<(String, Option<String>, Option<u16>), lat::Label_A>, sec::Secret<String, lat::Label_A>) = secret_structs::secret_block!(lat::Label_A {
        let u_config = unwrap_secret(serializable_config_yml);
        (wrap_secret((u_config.client_id, u_config.device_id, u_config.port)), wrap_secret(u_config.client_secret))
      });

      let (client_id, device_id, port) = decomposed_secret.0.declassify().get_value_consume();//.clone(); 
      self.client_id = client_id;
      self.client_secret = decomposed_secret.1;
      self.device_id = device_id;
      self.port = port;

      Ok(start)
    } else {

      if cfg!(debug_assertions) {

      println!("{}", BANNER);

      println!(
        "Config will be saved to {}",
        paths.config_file_path.display()
      );

      println!("\nHow to get setup:\n");

      let instructions = [
        "Go to the Spotify dashboard - https://developer.spotify.com/dashboard/applications",
        "Click `Create a Client ID` and create an app",
        "Now click `Edit Settings`",
        &format!(
          "Add `http://localhost:{}/callback` to the Redirect URIs",
          DEFAULT_PORT
        ),
        "You are now ready to authenticate with Spotify!",
      ];

      let mut number = 1;
      for item in instructions.iter() {
        println!("  {}. {}", number, item);
        number += 1;
      }

      }

      let client_id = ClientConfig::get_client_id_from_input()?;
      let client_secret = ClientConfig::get_client_secret_from_input()?;

      let mut port = String::new();
      #[cfg(debug_assertions)]
      println!("\nEnter port of redirect uri (default {}): ", DEFAULT_PORT);
      stdin().read_line(&mut port)?;
      let port = port.trim().parse::<u16>().unwrap_or(DEFAULT_PORT);
      
      let sc_temp = SerializableClientConfig {
        client_id: client_id, 
        client_secret: "".to_string(), 
        device_id: None,
        port: Some(port),
      };
      let mut serializable_config: sec::Secret<SerializableClientConfig, lat::Label_A> = secret_structs::secret_block!(lat::Label_A {
        wrap_secret(sc_temp)
      });

      secret_structs::secret_block_no_return!(lat::Label_A {
        let u_config = unwrap_secret_mut_ref(&mut serializable_config);
        u_config.client_secret = unwrap_secret(client_secret);
      });

      let mut new_config = fs::File::create(&paths.config_file_path)?;
      let serde_yaml_str = serde_yaml::to_string(serializable_config.declassify_ref())?;
      let content: sec::Secret<String, lat::Label_A> = secret_block!(lat::Label_A {wrap_secret(serde_yaml_str)});
      write!(new_config, "{}", content.declassify_ref())?;
      let (all_but_secret, client_secret) = secret_structs::secret_block!(lat::Label_A {
        let u_config = unwrap_secret(serializable_config);
        (wrap_secret((u_config.client_id, u_config.device_id, u_config.port)), wrap_secret(u_config.client_secret))
      });
      let (client_id, device_id, port) = all_but_secret.declassify().get_value_consume(); 

      self.client_id = client_id;
      self.client_secret = client_secret;
      self.device_id = device_id;
      self.port = port;

      Ok(std::time::Instant::now())
    }
  }

  fn get_client_id_from_input() -> Result<String> {
    let mut client_id = String::new();
    const MAX_RETRIES: u8 = 5;
    let mut num_retries = 0;
    loop {
      #[cfg(debug_assertions)]
      println!("\nEnter your Client ID: ");
      stdin().read_line(&mut client_id)?;
      client_id = client_id.trim().to_string();
      match ClientConfig::validate_client_id(&client_id) {
        Ok(_) => return Ok(client_id),
        Err(error_string) => {
          println!("{}", error_string);
          client_id.clear();
          num_retries += 1;
          if num_retries == MAX_RETRIES {
            return Err(Error::from(std::io::Error::new(
              std::io::ErrorKind::Other,
              format!("Maximum retries ({}) exceeded.", MAX_RETRIES),
            )));
          }
        }
      };
    }
  }

  fn validate_client_id(key: &str) -> Result<()> {
    const EXPECTED_LEN: usize = 32;
    if key.len() != EXPECTED_LEN {
      Err(Error::from(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!("invalid length: {} (must be {})", key.len(), EXPECTED_LEN,),
      )))
    } else if !key.chars().all(|c| c.is_digit(16)) {
      Err(Error::from(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "invalid character found (must be hex digits)",
      )))
    } else {
      Ok(())
    }
  }

  fn get_client_secret_from_input() -> Result<sec::Secret<String, lat::Label_A>> {
    let mut client_secret: sec::Secret<String, lat::Label_A> = secret_structs::secret_block!(lat::Label_A { wrap_secret(std::string::String::from("")) });
    const MAX_RETRIES: u8 = 5;
    let mut num_retries = 0;
    loop {
      #[cfg(debug_assertions)]
      println!("\nEnter your Client Secret: ");
      stdin().read_line(client_secret.declassify_ref_mut())?;
      client_secret = secret_structs::secret_block!(lat::Label_A {
        wrap_secret(str::to_string(str::trim(&unwrap_secret(client_secret))))
      });
      match ClientConfig::validate_client_secret(&client_secret) {
        Ok(_) => return Ok(client_secret),
        Err(error_string) => {
          println!("{}", error_string);
          client_secret = secret_structs::secret_block!(lat::Label_A {
            // TODO - get rid of clone?
            let mut u_client_secret = std::string::String::clone(unwrap_secret_mut_ref(&mut client_secret));
            std::string::String::clear(&mut u_client_secret);
            wrap_secret(u_client_secret)
          });

          num_retries += 1;
          if num_retries == MAX_RETRIES {
            return Err(Error::from(std::io::Error::new(
              std::io::ErrorKind::Other,
              format!("Maximum retries ({}) exceeded.", MAX_RETRIES),
            )));
          }
        }
      };
    }
  }

  fn validate_client_secret(key: &sec::Secret<String, lat::Label_A>) -> Result<()> {
    const EXPECTED_LEN: usize = 32;
    let sec_error_string = secret_structs::secret_block!(lat::Label_A {
      let u_key = unwrap_secret_ref(key);
      let mut is_hex = true;
      for c in str::chars(&u_key) {
        if !char::is_digit(c, 16) {
          is_hex = false;
        }
      }
      let mut error_string = std::string::String::from("");
      if std::string::String::len(&u_key) != EXPECTED_LEN {
        error_string = str::to_string("invalid length: ") + &*usize::to_string(&std::string::String::len(&u_key)) + &*str::to_string(" (must be ") + &*usize::to_string(&EXPECTED_LEN) + &*str::to_string(")");
      } else if !is_hex {
        error_string = std::string::String::from("invalid character found (must be hex digits)");
      } 
      wrap_secret(error_string)
    });

    let error_string = sec_error_string.declassify().get_value_consume(); 
    if !error_string.is_empty() {
      Err(Error::from(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        error_string,
      )))
    } else {
      Ok(())
    }
  }
}
