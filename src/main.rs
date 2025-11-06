use clap::{Parser, Subcommand};
use quantum_purse_key_vault::{types::SpxVariant, KeyVault, Util};
use rpassword::read_password;
use std::fs;
use std::io::{self, Write};

#[derive(Parser)]
#[command(name = "qpkv")]
#[command(about = "Quantum Purse Key Vault - SPHINCS+ key management CLI for CKB blockchain", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new wallet by generating a master seed
    Init {
        /// SPHINCS+ variant (Sha2128F, Sha2128S, Sha2192F, Sha2192S, Sha2256F, Sha2256S, Shake128F, Shake128S, Shake192F, Shake192S, Shake256F, Shake256S)
        #[arg(short, long)]
        variant: String,
    },
    /// ImportMnemonic a wallet from a seed phrase
    ImportMnemonic {
        /// SPHINCS+ variant
        #[arg(short, long)]
        variant: String,
        /// Path to file containing the seed phrase (optional, will prompt if not provided)
        #[arg(short, long)]
        seed_file: Option<String>,
    },
    /// ExportMnemonic the seed phrase
    ExportMnemonic {
        /// Output file path (optional, will print to stdout if not provided)
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Generate a new account
    NewAccount,
    /// List all accounts
    ListAccounts,
    /// Sign a message
    Sign {
        /// Lock args (account identifier)
        #[arg(short, long)]
        lock_args: String,
        /// Message to sign (hex-encoded)
        #[arg(short, long)]
        message: String,
    },
    /// Recover accounts
    Recover {
        /// Number of accounts to recover
        #[arg(short, long)]
        count: u32,
    },
    /// Generate account batch (for discovery)
    TryGenBatch {
        /// Start index
        #[arg(short, long)]
        start: u32,
        /// Count
        #[arg(short, long)]
        count: u32,
    },
    /// Clear all wallet data
    Clear,
    /// Check password strength
    CheckPassword,
    /// Display wallet information
    Info,
    /// Get CKB transaction message hash from mock transaction
    GetCkbTxMessage {
        /// Path to serialized mock transaction file
        #[arg(short, long)]
        tx_file: String,
    },
}

fn parse_variant(variant_str: &str) -> Result<SpxVariant, String> {
    match variant_str.to_lowercase().as_str() {
        "sha2128f" => Ok(SpxVariant::Sha2128F),
        "sha2128s" => Ok(SpxVariant::Sha2128S),
        "sha2192f" => Ok(SpxVariant::Sha2192F),
        "sha2192s" => Ok(SpxVariant::Sha2192S),
        "sha2256f" => Ok(SpxVariant::Sha2256F),
        "sha2256s" => Ok(SpxVariant::Sha2256S),
        "shake128f" => Ok(SpxVariant::Shake128F),
        "shake128s" => Ok(SpxVariant::Shake128S),
        "shake192f" => Ok(SpxVariant::Shake192F),
        "shake192s" => Ok(SpxVariant::Shake192S),
        "shake256f" => Ok(SpxVariant::Shake256F),
        "shake256s" => Ok(SpxVariant::Shake256S),
        _ => Err(format!("Invalid variant: {}", variant_str)),
    }
}

fn read_hidden_input(prompt: &str) -> Result<Vec<u8>, String> {
    print!("{}", prompt);
    io::stdout().flush().map_err(|e| e.to_string())?;
    let input = read_password().map_err(|e| e.to_string())?;
    Ok(input.into_bytes())
}

fn main() -> Result<(), String> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { variant } => {
            let variant = parse_variant(&variant)?;
            let vault = KeyVault::new(variant);

            println!("Initializing wallet with variant: {}", variant);
            println!("Required mnemonic words: {}", variant.required_bip39_size_in_word_total());

            let password = read_hidden_input("Enter password: ")?;
            let confirm = read_hidden_input("Confirm password: ")?;

            if password != confirm {
                return Err("Passwords do not match".to_string());
            }

            // Check password strength
            match Util::password_checker(password.clone()) {
                Ok(strength) => println!("Password strength: {} bits", strength),
                Err(e) => return Err(format!("Password validation failed: {}", e)),
            }

            vault.generate_master_seed(password)?;
            println!("✓ Master seed generated successfully");
            println!("⚠️  Make sure to backup your seed phrase using the 'export' command");
        }

        Commands::ImportMnemonic { variant, seed_file } => {
            let variant = parse_variant(&variant)?;
            let vault = KeyVault::new(variant);

            let seed_phrase = if let Some(file_path) = seed_file {
                fs::read_to_string(file_path).map_err(|e| e.to_string())?
            } else {
                String::from_utf8(read_hidden_input("Enter seed phrase: ")?)
                    .map_err(|e| e.to_string())?
            };

            let password = read_hidden_input("Enter password: ")?;
            let confirm = read_hidden_input("Confirm password: ")?;

            if password != confirm {
                return Err("Passwords do not match".to_string());
            }

            // Check password strength
            match Util::password_checker(password.clone()) {
                Ok(strength) => println!("Password strength: {} bits", strength),
                Err(e) => return Err(format!("Password validation failed: {}", e)),
            }

            vault.import_seed_phrase(seed_phrase.into_bytes(), password)?;
            println!("✓ Seed phrase imported successfully");
        }

        Commands::ExportMnemonic { output } => {
            let variant = KeyVault::get_stored_variant()?;
            let vault = KeyVault::new(variant);

            let password = read_hidden_input("Enter password: ")?;
            let seed_phrase = vault.export_seed_phrase(password)?;
            let seed_str = String::from_utf8(seed_phrase).map_err(|e| e.to_string())?;

            if let Some(output_path) = output {
                fs::write(output_path, &seed_str).map_err(|e| e.to_string())?;
                println!("✓ Seed phrase exported to file");
            } else {
                println!("Seed phrase:");
                println!("{}", seed_str);
            }
        }

        Commands::NewAccount => {
            let variant = KeyVault::get_stored_variant()?;
            let vault = KeyVault::new(variant);

            let password = read_hidden_input("Enter password: ")?;
            let lock_args = vault.gen_new_account(password)?;
            println!("✓ New account created");
            println!("Lock args: {}", lock_args);
        }

        Commands::ListAccounts => {
            let accounts = KeyVault::get_all_sphincs_lock_args()?;
            if accounts.is_empty() {
                println!("No accounts found");
            } else {
                println!("Accounts ({}):", accounts.len());
                for (idx, lock_args) in accounts.iter().enumerate() {
                    println!("  [{}] {}", idx, lock_args);
                }
            }
        }

        Commands::Sign {
            lock_args,
            message,
        } => {
            let variant = KeyVault::get_stored_variant()?;
            let vault = KeyVault::new(variant);

            let message_bytes = hex::decode(&message).map_err(|e| e.to_string())?;
            let password = read_hidden_input("Enter password: ")?;

            let signature = vault.sign(password, lock_args, message_bytes)?;
            println!("Signature: {}", hex::encode(signature));
        }

        Commands::Recover { count } => {
            let variant = KeyVault::get_stored_variant()?;
            let vault = KeyVault::new(variant);

            let password = read_hidden_input("Enter password: ")?;
            let accounts = vault.recover_accounts(password, count)?;

            println!("✓ Recovered {} accounts:", accounts.len());
            for (idx, lock_args) in accounts.iter().enumerate() {
                println!("  [{}] {}", idx, lock_args);
            }
        }

        Commands::TryGenBatch {
            start,
            count,
        } => {
            let variant = KeyVault::get_stored_variant()?;
            let vault = KeyVault::new(variant);

            let password = read_hidden_input("Enter password: ")?;
            let accounts = vault.try_gen_account_batch(password, start, count)?;

            println!("Generated {} lock args:", accounts.len());
            for (idx, lock_args) in accounts.iter().enumerate() {
                println!("  [{}] {}", start + idx as u32, lock_args);
            }
        }

        Commands::Clear => {
            print!("Are you sure you want to clear all wallet data? (yes/no): ");
            io::stdout().flush().map_err(|e| e.to_string())?;

            let mut confirmation = String::new();
            io::stdin().read_line(&mut confirmation).map_err(|e| e.to_string())?;

            if confirmation.trim().to_lowercase() == "yes" {
                KeyVault::clear_database()?;
                println!("✓ All wallet data cleared");
            } else {
                println!("Operation cancelled");
            }
        }

        Commands::CheckPassword => {
            let password = read_hidden_input("Enter password to check: ")?;
            match Util::password_checker(password) {
                Ok(strength) => {
                    println!("✓ Password is valid");
                    println!("Strength: {} bits", strength);
                }
                Err(e) => println!("✗ {}", e),
            }
        }

        Commands::Info => {
            let variant = KeyVault::get_stored_variant()?;
            let accounts = KeyVault::get_all_sphincs_lock_args()?;
            let data_path = quantum_purse_key_vault::db::get_data_dir()
                .map_err(|e| e.to_string())?;

            println!("Wallet Information:");
            println!("  SPHINCS+ Variant: {}", variant);
            println!("  Security Level: {} bits", variant.required_entropy_size_component() * 8);
            println!("  Mnemonic Words: {}", variant.required_bip39_size_in_word_total());
            println!("  Total Accounts: {}", accounts.len());
            println!("  Data Storage Path: {}", data_path.display());
        }

        Commands::GetCkbTxMessage { tx_file } => {
            let tx_data = fs::read(tx_file).map_err(|e| e.to_string())?;
            let message = Util::get_ckb_tx_message_all(tx_data)?;
            println!("CKB Tx message hash: {}", hex::encode(message));
        }
    }

    Ok(())
}
