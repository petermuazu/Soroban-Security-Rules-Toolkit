//! The admin setter authorizes the caller but never checks that the caller *is* the
//! admin: anyone can pass and sign for their own address and take over the contract.
#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env};

#[contracttype]
pub enum DataKey {
    Admin,
}

fn bump(e: &Env) {
    e.storage().instance().extend_ttl(17_280, 518_400);
}

#[contract]
pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn __constructor(e: Env, admin: Address) {
        e.storage().instance().set(&DataKey::Admin, &admin);
    }

    pub fn set_admin(e: Env, caller: Address, new_admin: Address) {
        caller.require_auth();
        e.storage().instance().set(&DataKey::Admin, &new_admin); // expect: SG-001
        e.events().publish((symbol_short!("admin"),), new_admin);
        bump(&e);
    }

    /// The fixed version: the caller must be the stored admin.
    pub fn set_admin_checked(e: Env, caller: Address, new_admin: Address) {
        caller.require_auth();
        let admin: Address = e.storage().instance().get(&DataKey::Admin).unwrap();
        if caller != admin {
            panic!("not admin");
        }
        e.storage().instance().set(&DataKey::Admin, &new_admin);
        e.events().publish((symbol_short!("admin"),), new_admin);
        bump(&e);
    }
}
