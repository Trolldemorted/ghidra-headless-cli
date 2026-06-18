//! Function tag commands (`ghidra.app.cmd.function`).

use clap::{Subcommand, ValueEnum};

use crate::client::Client;
use crate::json::Req;

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum TagField {
    Name,
    Comment,
}

impl TagField {
    fn wire(self) -> &'static str {
        match self {
            TagField::Name => "name",
            TagField::Comment => "comment",
        }
    }
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Create a new function tag program-wide
    Create {
        /// Target file project path
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        /// Tag name
        #[arg(long)]
        name: String,
        /// Tag comment [default: none]
        #[arg(long)]
        comment: Option<String>,
    },
    /// Delete a function tag program-wide
    Delete {
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        #[arg(long)]
        name: String,
    },
    /// Edit a tag's name or comment program-wide
    Change {
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        /// Existing tag name
        #[arg(long)]
        tag_name: String,
        /// New name or comment
        #[arg(long)]
        value: String,
        /// Which field to change [default: name]
        #[arg(long, value_enum)]
        field: Option<TagField>,
    },
    /// Add a tag to the function at an address
    Add {
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        #[arg(long)]
        tag: String,
        #[arg(long)]
        address: String,
    },
    /// Remove a tag from the function at an address
    Remove {
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        #[arg(long)]
        tag: String,
        #[arg(long)]
        address: String,
    },
}

pub fn run(cmd: Cmd, client: &Client) -> Result<(), ()> {
    match cmd {
        Cmd::Create {
            program,
            name,
            comment,
        } => client.run_simple(
            Req::new("CreateFunctionTagCmd")
                .str("file", program)
                .str("name", name)
                .opt_str("comment", comment)
                .build(),
        ),
        Cmd::Delete { program, name } => client.run_simple(
            Req::new("DeleteFunctionTagCmd")
                .str("file", program)
                .str("name", name)
                .build(),
        ),
        Cmd::Change {
            program,
            tag_name,
            value,
            field,
        } => client.run_simple(
            Req::new("ChangeFunctionTagCmd")
                .str("file", program)
                .str("tagName", tag_name)
                .str("value", value)
                .opt_str("field", field.map(|f| f.wire().to_string()))
                .build(),
        ),
        Cmd::Add {
            program,
            tag,
            address,
        } => client.run_simple(
            Req::new("AddFunctionTagCmd")
                .str("file", program)
                .str("tag", tag)
                .str("address", address)
                .build(),
        ),
        Cmd::Remove {
            program,
            tag,
            address,
        } => client.run_simple(
            Req::new("RemoveFunctionTagCmd")
                .str("file", program)
                .str("tag", tag)
                .str("address", address)
                .build(),
        ),
    }
}
