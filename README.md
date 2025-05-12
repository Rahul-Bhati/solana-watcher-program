# 🏅 Challenge-Based NFT Badge System (Solana + Anchor)

This is a smart contract built on Solana using the Anchor framework that issues **non-transferable NFTs (badges)** for completing challenges.

## 🎯 Core Idea

In Web2, users get badges/certificates (images) that are easy to fake or misuse.  
In this system, badges are minted as **NFTs tied to wallet addresses**, making them **verifiable and immutable**.

## 🛠️ What It Does

- Mints a **Welcome NFT** when a user registers.
- Admins can create new **challenge levels**.
- When a user completes a challenge (validated off-chain), an **NFT is minted** for that specific challenge.
- NFTs are **soulbound** (non-transferable), owned by the user wallet.


## ✅ Design Notes

- **No user data stored on-chain.** Challenge validation happens in backend/frontend.
- **NFTs are linked to wallet**, not username/email — ensuring proof-of-ownership.

## 💡 Use Cases

- Gamified learning platforms
- DAO contribution rewards
- Proof of milestone achievement

## 📌 Status

- [x] Welcome NFT minting
- [x] Admin creates challenges
- [x] Mint NFT when challenge completed
- [ ] Frontend integration
- [ ] Admin dashboard (WIP)

