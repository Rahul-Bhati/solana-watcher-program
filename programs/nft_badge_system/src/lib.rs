#![allow(unexpected_cfgs)]
use anchor_lang::prelude::*;
use anchor_spl::metadata::mpl_token_metadata::types::DataV2;
use anchor_spl::metadata::{create_metadata_accounts_v3, CreateMetadataAccountsV3, Metadata};
#[allow(unused_imports)]
use anchor_spl::token::{Mint, Token, TokenAccount};

declare_id!("ExxobJmjz8DuRNYgd5sq1jZzh5AuvmgmAd1MPv5sp2i");

#[program]
pub mod nft_badge_system {
    use super::*;

    /// Initializes the program with an admin.
    pub fn initialize(ctx: Context<Initialize>, admin_pubkey: Pubkey) -> Result<()> {
        let admin_config = &mut ctx.accounts.admin_config;
        if admin_config.initialized {
            return Err(ErrorCode::AlreadyInitialized.into());
        }
        admin_config.admin_pubkey = admin_pubkey;
        admin_config.initialized = true;
        msg!("Initialized admin config with admin: {}", admin_pubkey);
        Ok(())
    }

    /// Creates a new challenge with an associated reward NFT image URI (admin only).
    pub fn create_challenge(
        ctx: Context<CreateChallenge>,
        id: u64,
        name: String,
        description: String,
        level: u8,
        reward_nft_mint: Pubkey,
        image_uri: String,
    ) -> Result<()> {
        // Validate admin
        let admin_config = &ctx.accounts.admin_config;
        if admin_config.admin_pubkey != ctx.accounts.admin.key() {
            return Err(ErrorCode::Unauthorized.into());
        }

        // Validate inputs
        if name.len() > 32 || description.len() > 128 || image_uri.len() > 200 {
            return Err(ErrorCode::InvalidInput.into());
        }

        let challenge = &mut ctx.accounts.challenge;
        challenge.id = id;
        challenge.name = name;
        challenge.description = description;
        challenge.level = level;
        challenge.reward_nft_mint = reward_nft_mint;
        challenge.image_uri = image_uri;
        challenge.created_by = ctx.accounts.admin.key();
        msg!("Created challenge: {} (ID: {})", challenge.name, id);
        Ok(())
    }

    /// Updates a challenge's metadata (admin only).
    pub fn update_challenge(
        ctx: Context<UpdateChallenge>,
        challenge_id: u64,
        name: String,
        description: String,
        level: u8,
        reward_nft_mint: Pubkey,
        image_uri: String,
    ) -> Result<()> {
        // Validate admin
        let admin_config = &ctx.accounts.admin_config;
        if admin_config.admin_pubkey != ctx.accounts.admin.key() {
            return Err(ErrorCode::Unauthorized.into());
        }

        // Validate inputs
        if name.len() > 32 || description.len() > 128 || image_uri.len() > 200 {
            return Err(ErrorCode::InvalidInput.into());
        }

        let challenge = &mut ctx.accounts.challenge;
        if challenge.id != challenge_id {
            return Err(ErrorCode::ChallengeNotFound.into());
        }

        challenge.name = name;
        challenge.description = description;
        challenge.level = level;
        challenge.reward_nft_mint = reward_nft_mint;
        challenge.image_uri = image_uri;
        msg!(
            "Updated challenge: {} (ID: {})",
            challenge.name,
            challenge_id
        );
        Ok(())
    }

    /// Deletes a challenge (admin only).
    pub fn delete_challenge(ctx: Context<DeleteChallenge>, challenge_id: u64) -> Result<()> {
        // Validate admin
        let admin_config = &ctx.accounts.admin_config;
        if admin_config.admin_pubkey != ctx.accounts.admin.key() {
            return Err(ErrorCode::Unauthorized.into());
        }

        let challenge = &ctx.accounts.challenge;
        if challenge.id != challenge_id {
            return Err(ErrorCode::ChallengeNotFound.into());
        }

        msg!(
            "Deleted challenge: {} (ID: {})",
            challenge.name,
            challenge_id
        );
        // Account is closed by Anchor when the instruction completes
        Ok(())
    }

    /// Mints a non-transferable NFT for a user for a specific challenge (Welcome NFT or challenge NFT).
    pub fn mint_nft(ctx: Context<MintNFT>, challenge_id: u64) -> Result<()> {
        let nft_badge = &mut ctx.accounts.nft_badge;
        let challenge = &ctx.accounts.challenge;

        // Check if badge already exists
        if nft_badge.mint != Pubkey::default() {
            return Err(ErrorCode::BadgeAlreadyMinted.into());
        }

        // Verify challenge exists
        if challenge.id != challenge_id {
            return Err(ErrorCode::ChallengeNotFound.into());
        }

        // Validate token account
        if ctx.accounts.token_account.owner != ctx.accounts.user.key()
            || ctx.accounts.token_account.mint != ctx.accounts.mint.key()
        {
            return Err(ErrorCode::InvalidTokenAccount.into());
        }

        // Initialize NFT badge
        nft_badge.mint = ctx.accounts.mint.key();
        nft_badge.owner = ctx.accounts.user.key();
        nft_badge.challenge_id = challenge_id;
        nft_badge.non_transferable = true;

        // Mint one token to the user's token account
        let bump = ctx.bumps.mint_authority;
        let binding = &[bump]; // Ensure this is a reference
        let signer_seeds: &[&[&[u8]]] = &[&[b"mint_authority".as_ref(), binding][..]];

        anchor_spl::token::mint_to(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                anchor_spl::token::MintTo {
                    mint: ctx.accounts.mint.to_account_info(),
                    to: ctx.accounts.token_account.to_account_info(),
                    authority: ctx.accounts.mint_authority.to_account_info(),
                },
                signer_seeds,
            ),
            1, // Mint 1 token (NFT)
        )?;

        // Create metadata for the NFT
        let cpi_program = ctx.accounts.metadata_program.to_account_info();
        let cpi_accounts = CreateMetadataAccountsV3 {
            metadata: ctx.accounts.metadata.to_account_info(),
            mint: ctx.accounts.mint.to_account_info(),
            mint_authority: ctx.accounts.mint_authority.to_account_info(),
            payer: ctx.accounts.user.to_account_info(),
            update_authority: ctx.accounts.mint_authority.to_account_info(),
            system_program: ctx.accounts.system_program.to_account_info(),
            rent: ctx.accounts.rent.to_account_info(),
        };
        let cpi_context = CpiContext::new_with_signer(cpi_program, cpi_accounts, signer_seeds);

        let nft_name = if challenge_id == 0 {
            "Welcome NFT".to_string()
        } else {
            challenge.name.clone()
        };
        let nft_symbol = if challenge_id == 0 { "WNFT" } else { "CNFT" };

        create_metadata_accounts_v3(
            cpi_context,
            DataV2 {
                name: nft_name,
                symbol: nft_symbol.to_string(),
                uri: challenge.image_uri.clone(),
                seller_fee_basis_points: 0,
                creators: None,
                collection: None,
                uses: None,
            },
            true, // is_mutable
            true, // update_authority_is_signer
            None, // collection_details
        )?;

        msg!(
            "Minted NFT for user: {}, challenge ID: {}",
            ctx.accounts.user.key(),
            challenge_id
        );
        Ok(())
    }
}

// Account Structures
#[account]
pub struct AdminConfig {
    pub admin_pubkey: Pubkey,
    pub initialized: bool,
}

#[account]
pub struct Challenge {
    pub id: u64,
    pub name: String,
    pub description: String,
    pub level: u8,
    pub reward_nft_mint: Pubkey,
    pub image_uri: String,
    pub created_by: Pubkey,
}

#[account]
pub struct NFTBadge {
    pub mint: Pubkey,
    pub owner: Pubkey,
    pub challenge_id: u64, // 0 for Welcome NFT
    pub non_transferable: bool,
}

#[account]
pub struct MintAuthority {
    pub bump: u8,
}

// Error Codes
#[error_code]
pub enum ErrorCode {
    #[msg("Only admin can perform this action")]
    Unauthorized,
    #[msg("Program already initialized")]
    AlreadyInitialized,
    #[msg("Challenge does not exist")]
    ChallengeNotFound,
    #[msg("Invalid input data")]
    InvalidInput,
    #[msg("Badge already minted")]
    BadgeAlreadyMinted,
    #[msg("Invalid mint authority")]
    InvalidMintAuthority,
    #[msg("Invalid token account")]
    InvalidTokenAccount,
    #[msg("Bump seed not found")]
    BumpSeedNotFound,
}

// Instruction Contexts
#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = admin,
        space = 8 + 32 + 1,
        seeds = [b"admin_config"],
        bump
    )]
    pub admin_config: Account<'info, AdminConfig>,
    #[account(mut)]
    pub admin: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(id: u64)]
pub struct CreateChallenge<'info> {
    #[account(
        init,
        payer = admin,
        space = 8 + 8 + 32 + 128 + 1 + 32 + 200 + 32,
        seeds = [b"challenge", id.to_le_bytes().as_ref()],
        bump
    )]
    pub challenge: Account<'info, Challenge>,
    #[account(
        constraint = admin_config.admin_pubkey == admin.key() @ ErrorCode::Unauthorized
    )]
    pub admin_config: Account<'info, AdminConfig>,
    #[account(mut)]
    pub admin: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(challenge_id: u64)]
pub struct UpdateChallenge<'info> {
    #[account(
        mut,
        seeds = [b"challenge", challenge_id.to_le_bytes().as_ref()],
        bump
    )]
    pub challenge: Account<'info, Challenge>,
    #[account(
        constraint = admin_config.admin_pubkey == admin.key() @ ErrorCode::Unauthorized
    )]
    pub admin_config: Account<'info, AdminConfig>,
    #[account(mut)]
    pub admin: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(challenge_id: u64)]
pub struct DeleteChallenge<'info> {
    #[account(
        mut,
        seeds = [b"challenge", challenge_id.to_le_bytes().as_ref()],
        bump,
        close = admin
    )]
    pub challenge: Account<'info, Challenge>,
    #[account(
        constraint = admin_config.admin_pubkey == admin.key() @ ErrorCode::Unauthorized
    )]
    pub admin_config: Account<'info, AdminConfig>,
    #[account(mut)]
    pub admin: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(challenge_id: u64)]
pub struct MintNFT<'info> {
    #[account(
        init,
        payer = user,
        space = 8 + 32 + 32 + 8 + 1,
        seeds = [b"nft_badge", user.key().as_ref(), challenge_id.to_le_bytes().as_ref()],
        bump
    )]
    pub nft_badge: Account<'info, NFTBadge>,
    #[account(
        seeds = [b"challenge", challenge_id.to_le_bytes().as_ref()],
        bump
    )]
    pub challenge: Account<'info, Challenge>,

    #[account(
        init,
        payer = user,
        mint::decimals = 0,
        mint::authority = mint_authority.key(),
        mint::freeze_authority = mint_authority.key(),
    )]
    pub mint: Account<'info, Mint>,

    #[account(mut)]
    pub token_account: Account<'info, TokenAccount>,

    /// CHECK: Safe because we are just checking the seeds
    #[account(
       seeds = [b"mint_authority"],
        bump
    )]
    pub mint_authority: AccountInfo<'info>,
    #[account(mut)]
    pub user: Signer<'info>,
    /// CHECK: This will be initialized by the metadata program
    #[account(mut)]
    pub metadata: UncheckedAccount<'info>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
    pub metadata_program: Program<'info, Metadata>,
}
