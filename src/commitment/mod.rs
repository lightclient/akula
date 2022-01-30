pub mod gen;
pub mod rlputil;

use self::rlputil::*;
use crate::{crypto::keccak256, models::*, static_left_pad, u256_to_h256, zeroless_view};
use anyhow::{bail, format_err};
use array_macro::array;
use arrayref::array_ref;
use arrayvec::ArrayVec;
use bytes::{BufMut, BytesMut};
use derive_more::From;
use gen::*;
use sha3::{Digest, Keccak256};
use std::{
    collections::HashMap,
    ops::{Generator, GeneratorState},
    pin::Pin,
    ptr::addr_of_mut,
};
use tracing::trace;

pub trait Trie {
    type Hash;

    fn process_updates(
        &mut self,
        plain_keys: &[u8],
        hashed_keys: &[u8],
        updates: &[Update],
    ) -> HashMap<Vec<u8>, Vec<u8>>;

    /// Produce root hash of the trie
    fn root_hash(&self) -> anyhow::Result<Self::Hash>;

    /// Drop everything from the trie
    fn reset(&mut self);
}

fn uvarint(buf: &[u8]) -> Option<(u64, usize)> {
    let mut x = 0;
    let mut s = 0;
    for (i, b) in buf.iter().copied().enumerate() {
        if i == 10 {
            return None;
        }
        if b < 0x80 {
            if i == 9 && b > 1 {
                return None;
            }
            return Some(((x | b << s).into(), i + 1));
        }
        x |= (b & 0x7f) << s as u64;
        s += 7;
    }
    Some((0, 0))
}

fn encode_uvarint(out: &mut Vec<u8>, mut x: u64) {
    while x >= 0x80 {
        out.push(x as u8 | 0x80);
        x >>= 7;
    }
    out.push(x as u8);
}

fn encode_slice(out: &mut Vec<u8>, s: &[u8]) {
    encode_uvarint(out, s.len() as u64);
    out.extend_from_slice(s);
}

impl Account {
    pub fn decode2(buffer: &[u8]) -> Self {
        let mut pos = 0_usize;
        let nonce = if buffer[pos] < 128 {
            buffer[pos].into()
        } else {
            let size_bytes = usize::from(buffer[pos] - 128);
            pos += 1;
            let (nonce, n) = uvarint(&buffer[pos..pos + size_bytes]).unwrap();
            pos += n;

            nonce
        };

        let balance = if buffer[pos] < 128 {
            let balance = buffer[pos].into();
            pos += 1;

            balance
        } else {
            let bc = usize::from(buffer[pos] - 128);
            pos += 1;
            let balance = U256::from_be_bytes(static_left_pad(&buffer[pos..pos + bc]));
            pos += bc;

            balance
        };

        let code_size = usize::from(buffer[pos] - 128);
        let code_hash = if code_size > 0 {
            pos += 1;
            H256(static_left_pad(&buffer[pos..pos + code_size]))
        } else {
            H256::zero()
        };

        Self {
            nonce,
            balance,
            code_hash,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Cell {
    h: Option<H256>,              // Cell hash
    apk: Option<Address>,         // account plain key
    spk: Option<(Address, H256)>, // storage plain key
    down_hashed_key: ArrayVec<u8, 128>,
    extension: ArrayVec<u8, 64>,
    pub nonce: u64,
    pub balance: U256,
    pub code_hash: H256, // hash of the bytecode
    pub storage: Option<U256>,
}

impl Default for Cell {
    fn default() -> Self {
        Self {
            h: None,
            apk: None,
            spk: None,
            down_hashed_key: Default::default(),
            extension: Default::default(),
            nonce: Default::default(),
            balance: Default::default(),
            code_hash: EMPTY_HASH,
            storage: Default::default(),
        }
    }
}

impl Cell {
    fn compute_hash_len(&self, depth: usize) -> usize {
        if self.spk.is_some() && depth >= 64 {
            let key_len = 128 - depth + 1; // Length of hex key with terminator character
            let compact_len = (key_len - 1) / 2 + 1;
            let (kp, kl) = if compact_len > 1 {
                (1, compact_len)
            } else {
                (0, 1)
            };
            let storage_val = self.storage.map(u256_to_h256).unwrap_or_default();
            let val = RlpSerializableBytes(zeroless_view(&storage_val));
            let total_len = kp + kl + val.double_rlp_len();
            let pt = generate_struct_len(total_len).len();
            if total_len + pt < KECCAK_LENGTH {
                return total_len + pt;
            }
        }
        KECCAK_LENGTH + 1
    }

    // fn account_for_hashing(&self, storage_root_hash: H256) -> ArrayVec<u8, 128> {
    //     let mut buffer = ArrayVec::new();

    //     let mut balanceBytes = 0;
    //     if self.balance >= 128 {
    //         balanceBytes = ((U256::BITS - self.balance.leading_zeros() + 7) / 8) as u8;
    //     }

    //     let mut nonceBytes = 0;
    //     if self.nonce < 128 && self.nonce != 0 {
    //         nonceBytes = 0;
    //     } else {
    //         nonceBytes = (((U256::BITS - self.nonce.leading_zeros()) + 7) / 8) as u8;
    //     }

    //     let mut structLength = balanceBytes + nonceBytes + 2;
    //     structLength += 66; // Two 32-byte arrays + 2 prefixes

    //     if structLength < 56 {
    //         buffer.try_push(192 + structLength).unwrap();
    //     } else {
    //         let lengthBytes = ((u8::BITS - structLength.leading_zeros() + 7) / 8) as u8;
    //         buffer.try_push(247 + lengthBytes).unwrap();

    //         let mut i = lengthBytes;
    //         while i > 0 {
    //             buffer.try_push(structLength as u8);
    //             structLength >>= 8;
    //             i -= 1;
    //         }
    //     }

    // // Encoding nonce
    // if cell.Nonce < 128 && cell.Nonce != 0 {
    // 	buffer[pos] = byte(cell.Nonce)
    // } else {
    // 	buffer[pos] = byte(128 + nonceBytes)
    // 	var nonce = cell.Nonce
    // 	for i := nonceBytes; i > 0; i-- {
    // 		buffer[pos+i] = byte(nonce)
    // 		nonce >>= 8
    // 	}
    // }
    // pos += 1 + nonceBytes

    // // Encoding balance
    // if cell.Balance.LtUint64(128) && !cell.Balance.IsZero() {
    // 	buffer[pos] = byte(cell.Balance.Uint64())
    // 	pos++
    // } else {
    // 	buffer[pos] = byte(128 + balanceBytes)
    // 	pos++
    // 	cell.Balance.WriteToSlice(buffer[pos : pos+balanceBytes])
    // 	pos += balanceBytes
    // }

    // // Encoding Root and CodeHash
    // buffer[pos] = 128 + 32
    // pos++
    // copy(buffer[pos:], storageRootHash[:])
    // pos += 32
    // buffer[pos] = 128 + 32
    // pos++
    // copy(buffer[pos:], cell.CodeHash[:])
    // pos += 32
    // return pos

    //     buffer
    // }
}

#[derive(Debug)]
struct CellGrid {
    root: Cell, // Root cell of the tree
    // Rows of the grid correspond to the level of depth in the patricia tree
    // Columns of the grid correspond to pointers to the nodes further from the root
    grid: [[Cell; 16]; 128], // First 64 rows of this grid are for account trie, and next 64 rows are for storage trie
}

impl Default for CellGrid {
    fn default() -> Self {
        Self {
            root: Cell::default(),
            grid: array![array![Cell::default(); 16]; 128],
        }
    }
}

impl CellGrid {
    #[inline(always)]
    fn cell_mut(&mut self, cell_position: Option<CellPosition>) -> &mut Cell {
        if let Some(position) = cell_position {
            self.grid_cell_mut(position)
        } else {
            &mut self.root
        }
    }

    #[inline(always)]
    fn grid_cell_mut(&mut self, cell_position: CellPosition) -> &mut Cell {
        &mut self.grid[cell_position.row as usize][cell_position.col as usize]
    }

    #[inline(always)]
    fn cell_mut_ptr(&mut self, cell_position: Option<CellPosition>) -> *mut Cell {
        if let Some(position) = cell_position {
            self.grid_cell_mut(position)
        } else {
            addr_of_mut!(self.root)
        }
    }

    #[inline(always)]
    fn grid_cell_mut_ptr(&mut self, cell_position: CellPosition) -> *mut Cell {
        addr_of_mut!(self.grid[cell_position.row as usize][cell_position.col as usize])
    }

    fn fill_from_upper_cell(
        &mut self,
        cell: Option<CellPosition>,
        up_cell: Option<CellPosition>,
        depth: usize,
        depth_increment: usize,
    ) {
        let up_cell = self.cell_mut(up_cell).clone();
        let cell = self.cell_mut(cell);

        cell.down_hashed_key.clear();
        if up_cell.down_hashed_key.len() > depth_increment {
            cell.down_hashed_key
                .try_extend_from_slice(&up_cell.down_hashed_key[depth_increment..])
                .unwrap();
        }
        cell.extension.clear();
        if up_cell.extension.len() > depth_increment {
            cell.extension
                .try_extend_from_slice(&up_cell.extension[depth_increment..])
                .unwrap();
        }
        if depth <= 64 {
            cell.apk = up_cell.apk;
            if up_cell.apk.is_some() {
                cell.balance = up_cell.balance;
                cell.nonce = up_cell.nonce;
                cell.code_hash = up_cell.code_hash;
                cell.extension = up_cell.extension;
            }
        } else {
            cell.apk = None;
        }
        cell.spk = up_cell.spk;
        if up_cell.spk.is_some() {
            cell.storage = up_cell.storage;
        }
        cell.h = up_cell.h;
    }

    fn fill_from_lower_cell(
        &mut self,
        cell: Option<CellPosition>,
        low_cell: CellPosition,
        low_depth: usize,
        pre_extension: &[u8],
        nibble: usize,
    ) {
        let low_cell = self.grid_cell_mut(low_cell).clone();
        let cell = self.cell_mut(cell);

        if low_cell.apk.is_some() || low_depth < 64 {
            cell.apk = low_cell.apk;
        }
        if low_cell.apk.is_some() {
            cell.balance = low_cell.balance;
            cell.nonce = low_cell.nonce;
            cell.code_hash = low_cell.code_hash;
        }
        cell.spk = low_cell.spk;
        if low_cell.spk.is_some() {
            cell.storage = low_cell.storage;
        }
        if low_cell.h.is_some() {
            if (low_cell.apk.is_none() && low_depth < 64)
                || (low_cell.spk.is_none() && low_depth > 64)
            {
                // Extension is related to either accounts branch node, or storage branch node, we prepend it by preExtension | nibble
                cell.extension.clear();
                cell.extension.try_extend_from_slice(pre_extension).unwrap();
                cell.extension.push(nibble as u8);
                cell.extension
                    .try_extend_from_slice(&low_cell.extension)
                    .unwrap();
            } else {
                // Extension is related to a storage branch node, so we copy it upwards as is
                cell.extension = low_cell.extension;
            }
        }
        cell.h = low_cell.h;
    }
}

fn hash_key(plain_key: &[u8], hashed_key_offset: usize) -> ArrayVec<u8, 32> {
    let hash_buf = keccak256(plain_key).0;
    let mut hash_buf = &hash_buf[hashed_key_offset / 2..];
    let mut dest = ArrayVec::new();
    if hashed_key_offset % 2 == 1 {
        dest.push(hash_buf[0] & 0xf);
        hash_buf = &hash_buf[1..];
    }
    for c in hash_buf {
        dest.push((c >> 4) & 0xf);
        dest.push(c & 0xf);
    }

    dest
}

/// HexPatriciaHashed implements commitment based on patricia merkle tree with radix 16,
/// with keys pre-hashed by keccak256
#[derive(Debug)]
pub struct HexPatriciaHashed {
    grid: CellGrid,
    // How many rows (starting from row 0) are currently active and have corresponding selected columns
    // Last active row does not have selected column
    active_rows: usize,
    // Length of the key that reflects current positioning of the grid. It maybe larger than number of active rows,
    // if a account leaf cell represents multiple nibbles in the key
    current_key: ArrayVec<u8, 128>, // For each row indicates which column is currently selected
    depths: [usize; 128],           // For each row, the depth of cells in that row
    root_checked: bool, // Set to false if it is not known whether the root is empty, set to true if it is checked
    root_touched: bool,
    root_present: bool,
    branch_before: [bool; 128], // For each row, whether there was a branch node in the database loaded in unfold
    touch_map: [u16; 128], // For each row, bitmap of cells that were either present before modification, or modified or deleted
    after_map: [u16; 128], // For each row, bitmap of cells that were present after modification
    // Function used to load branch node and fill up the cells
    // For each cell, it sets the cell type, clears the modified flag, fills the hash,
    // and for the extension, account, and leaf type, the `l` and `k`
    // branchFn: Box<dyn Fn(prefix: &[u8]) -> func(prefix []byte) ([]byte, error)
    // Function used to fetch account with given plain key. It loads
    // accountFn func(plainKey []byte, cell *Cell) error
    // Function used to fetch account with given plain key
    // storageFn       func(plainKey []byte, cell *Cell) error
    // keccak          keccakState
    // keccak2         keccakState
    account_key_len: usize,
    byte_array_writer: BytesMut,
}

impl Default for HexPatriciaHashed {
    fn default() -> Self {
        Self {
            grid: Default::default(),
            active_rows: Default::default(),
            current_key: Default::default(),
            depths: [0; 128],
            root_checked: Default::default(),
            root_touched: Default::default(),
            root_present: Default::default(),
            branch_before: [false; 128],
            touch_map: [0; 128],
            after_map: [0; 128],
            account_key_len: Default::default(),
            byte_array_writer: Default::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct CellPosition {
    row: usize,
    col: usize,
}

#[derive(Clone, Debug)]
pub struct Update {
    pub flags: UpdateFlags,
    pub balance: U256,
    pub nonce: u64,
    pub code_hash_or_storage: ArrayVec<u8, 32>,
}

impl Update {
    fn decode(buf: &[u8], mut pos: usize) -> anyhow::Result<(Self, usize)> {
        if buf.len() < pos + 1 {
            bail!("decode Update: buffer too small for flags")
        }
        let flags = buf[pos];
        pos += 1;

        let mut u = Update {
            flags,
            balance: U256::ZERO,
            nonce: 0,
            code_hash_or_storage: ArrayVec::new(),
        };
        if flags & BALANCE_UPDATE != 0 {
            if buf.len() < pos + 1 {
                bail!("decode Update: buffer too small for balance len");
            }
            let balance_len = buf[pos] as usize;
            pos += 1;
            if buf.len() < pos + balance_len {
                bail!("decode Update: buffer too small for balance");
            }
            u.balance = U256::from_be_bytes(static_left_pad(&buf[pos..pos + balance_len]));
            pos += balance_len;
        }

        if flags & NONCE_UPDATE != 0 {
            let (nonce_v, n) =
                uvarint(&buf[pos..]).ok_or_else(|| format_err!("decode Update: nonce overflow"))?;
            if n == 0 {
                bail!("decode Update: buffer too small for nonce")
            }
            u.nonce = nonce_v;
            pos += n;
        }

        if flags & CODE_UPDATE != 0 {
            if buf.len() < pos + 32 {
                bail!("decode Update: buffer too small for codeHash");
            }
            u.code_hash_or_storage.copy_from_slice(&buf[pos..pos + 32]);
            pos += 32;
        }

        if flags & STORAGE_UPDATE != 0 {
            let (l, n) = uvarint(&buf[pos..])
                .ok_or_else(|| format_err!("decode Update: storage lee overflow"))?;
            if n == 0 {
                bail!("decode Update: buffer too small for storage len");
            }
            pos += n;

            let l = l as usize;
            if buf.len() < pos + l {
                bail!("decode Update: buffer too small for storage");
            }
            u.code_hash_or_storage[..l].copy_from_slice(&buf[pos..pos + l]);
            pos += l;
        }

        Ok((u, pos))
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = vec![self.flags];
        if self.flags & BALANCE_UPDATE != 0 {
            let encoded_balance = self.balance.to_be_bytes();
            let s = zeroless_view(&encoded_balance);
            out.push(s.len() as u8);
            out.extend_from_slice(s);
        }
        if self.flags & NONCE_UPDATE != 0 {
            encode_uvarint(&mut out, self.nonce);
        }
        if self.flags & CODE_UPDATE != 0 {
            out.extend_from_slice(&self.code_hash_or_storage);
        }
        if self.flags & STORAGE_UPDATE != 0 {
            encode_slice(&mut out, &*self.code_hash_or_storage);
        }

        out
    }
}

#[derive(Clone, Debug)]
pub struct ProcessUpdateArg {
    pub hashed_key: H256,
    pub plain_key: Vec<u8>,
    pub update: Update,
}

impl HexPatriciaHashed {
    pub fn root_hash(&mut self) -> H256 {
        H256::from_slice(&self.compute_cell_hash(None, 0)[1..])
    }

    pub fn process_updates(
        &mut self,
        updates: Vec<ProcessUpdateArg>,
    ) -> StartedInterrupt<'_, HashMap<Vec<u8>, Vec<u8>>> {
        let inner = move |_| {
            let mut branch_node_updates = HashMap::new();

            for ProcessUpdateArg {
                hashed_key,
                plain_key,
                update,
            } in updates
            {
                trace!(
                    "plain_key={:?}, hashed_key={:?}, current_key={:?}, update={:?}",
                    plain_key,
                    hashed_key,
                    hex::encode(&self.current_key),
                    update
                );

                // Keep folding until the currentKey is the prefix of the key we modify
                while self.need_folding(hashed_key) {
                    let (branch_node_update, update_key) = self.fold();
                    if let Some(branch_node_update) = branch_node_update {
                        branch_node_updates.insert(update_key, branch_node_update);
                    }
                }
            }

            yield InterruptData::LoadBranch { prefix: vec![] };

            branch_node_updates
        };

        StartedInterrupt {
            inner: Box::new(inner),
        }
    }

    fn compute_cell_hash(&mut self, pos: Option<CellPosition>, depth: usize) -> ArrayVec<u8, 33> {
        let cell = self.grid.cell_mut(pos);
        let mut storage_root = None;
        if let Some((address, location)) = cell.spk {
            let mut spk = [0; 52];
            // ????
            spk[..20].copy_from_slice(&address.0);
            spk[20..].copy_from_slice(&location.0);
            let hashed_key_offset = depth.saturating_sub(64);
            let singleton = depth <= 64;
            cell.down_hashed_key.clear();
            cell.down_hashed_key
                .try_extend_from_slice(&hash_key(&spk[self.account_key_len..], hashed_key_offset))
                .unwrap();
            cell.down_hashed_key[64 - hashed_key_offset] = 16; // Add terminator
            if singleton {
                trace!(
                    "leafHashWithKeyVal(singleton) for [{}]=>[{:?}]",
                    hex::encode(&cell.down_hashed_key[..64 - hashed_key_offset + 1]),
                    cell.storage
                );
                storage_root = Some(H256::from_slice(
                    &leaf_hash_with_key_val(
                        &cell.down_hashed_key[..64 - hashed_key_offset + 1],
                        RlpSerializableBytes(&cell.storage.unwrap().to_be_bytes()),
                        true,
                    )[1..],
                ));
            } else {
                trace!(
                    "leafHashWithKeyVal for [{}]=>[{:?}]",
                    hex::encode(&cell.down_hashed_key[..64 - hashed_key_offset + 1]),
                    cell.storage
                );
                return leaf_hash_with_key_val(
                    &cell.down_hashed_key[..64 - hashed_key_offset + 1],
                    RlpSerializableBytes(&cell.storage.unwrap().to_be_bytes()),
                    false,
                );
            }
        }
        if let Some(apk) = cell.apk {
            cell.down_hashed_key.clear();
            cell.down_hashed_key
                .try_extend_from_slice(&hash_key(&apk.0, depth))
                .unwrap();
            cell.down_hashed_key[64 - depth] = 16; // Add terminator

            let storage_root = storage_root.unwrap_or_else(|| {
                if !cell.extension.is_empty() {
                    // Extension
                    let h = cell.h.expect("computeCellHash extension without hash");
                    trace!(
                        "extension_hash for [{}]=>[{:?}]\n",
                        hex::encode(&cell.extension),
                        h
                    );
                    extension_hash(&cell.extension, h)
                } else if let Some(h) = cell.h {
                    h
                } else {
                    EMPTY_ROOT
                }
            });
            let account_rlp = fastrlp::encode_fixed_size(&RlpAccount {
                storage_root,
                nonce: cell.nonce,
                balance: cell.balance,
                code_hash: cell.code_hash,
            });
            trace!(
                "accountLeafHashWithKey for [{}]=>[{}]\n",
                hex::encode(&cell.down_hashed_key[..65 - depth]),
                hex::encode(&account_rlp)
            );
            account_leaf_hash_with_key(
                &cell.down_hashed_key[..65 - depth],
                RlpEncodableBytes(&account_rlp),
            );
        }

        let mut buf = ArrayVec::new();
        buf.push(0x80 + 32);
        if !cell.extension.is_empty() {
            // Extension
            let cell_hash = cell.h.expect("compute_cell_hash extension without hash");
            trace!(
                "extensionHash for [{}]=>[{:?}]",
                hex::encode(&cell.extension),
                cell_hash
            );
            buf.try_extend_from_slice(&extension_hash(&cell.extension, cell_hash).0)
                .unwrap();
        } else if let Some(cell_hash) = cell.h {
            buf.try_extend_from_slice(&cell_hash[..]).unwrap();
        } else {
            buf.try_extend_from_slice(&EMPTY_HASH[..]).unwrap();
        }

        buf
    }

    fn need_folding(&self, hashed_key: H256) -> bool {
        !hashed_key[..].starts_with(&self.current_key[..])
    }

    pub(crate) fn fold(&mut self) -> (Option<Vec<u8>>, Vec<u8>) {
        assert_ne!(self.active_rows, 0, "cannot fold - no active rows");
        trace!(
            "fold: active_rows: {}, current_key: [{:?}], touch_map: {:#018b}, after_map: {:#018b}",
            self.active_rows,
            hex::encode(&self.current_key[..]),
            self.touch_map[self.active_rows - 1],
            self.after_map[self.active_rows - 1]
        );
        // Move information to the row above
        let row = self.active_rows - 1;
        let mut col = 0;
        let mut up_depth = 0;
        let up_cell = if self.active_rows == 1 {
            trace!("upcell is root");

            None
        } else {
            up_depth = self.depths[self.active_rows - 2];
            col = self.current_key[up_depth - 1];

            trace!("upcell is ({} x {}), upDepth={}", row - 1, col, up_depth);

            Some(CellPosition {
                row: row - 1,
                col: col as usize,
            })
        };
        let depth = self.depths[self.active_rows - 1];
        let mut branch_data = None;

        let update_key = hex_to_compact(&self.current_key);
        trace!(
            "touch_map[{}]={:#018b}, after_map[{}]={:#018b}",
            row,
            self.touch_map[row],
            row,
            self.after_map[row]
        );

        let parts_count = self.after_map[row].count_ones();
        match parts_count {
            0 => {
                // Everything deleted
                if self.touch_map[row] != 0 {
                    if row == 0 {
                        // Root is deleted because the tree is empty
                        self.root_touched = true;
                        self.root_present = false;
                    } else if up_depth == 64 {
                        // Special case - all storage items of an account have been deleted, but it does not automatically delete the account, just makes it empty storage
                        // Therefore we are not propagating deletion upwards, but turn it into a modification
                        self.touch_map[row - 1] |= 1_u16 << col;
                    } else {
                        // Deletion is propagated upwards
                        self.touch_map[row - 1] |= 1_u16 << col;
                        self.after_map[row - 1] &= !(1_u16 << col);
                    }
                }
                self.grid.cell_mut(up_cell).h = None;
                self.grid.cell_mut(up_cell).apk = None;
                self.grid.cell_mut(up_cell).spk = None;
                self.grid.cell_mut(up_cell).extension.clear();
                self.grid.cell_mut(up_cell).down_hashed_key.clear();
                if self.branch_before[row] {
                    let mut bitmap_buf = Vec::with_capacity(2 + 2);
                    bitmap_buf.extend_from_slice(&self.touch_map[row].to_be_bytes()); // touch_map
                    bitmap_buf.extend_from_slice(&0_u16.to_be_bytes()); // after_map
                    branch_data = Some(bitmap_buf);
                }
                self.active_rows -= 1;
                if up_depth > 0 {
                    self.current_key.truncate(up_depth - 1);
                } else {
                    self.current_key.clear();
                }
            }
            1 => {
                // Leaf or extension node
                if self.touch_map[row] != 0 {
                    // any modifications
                    if row == 0 {
                        self.root_touched = true;
                    } else {
                        // Modification is propagated upwards
                        self.touch_map[row - 1] |= 1_u16 << col;
                    }
                }
                let nibble = self.after_map[row].trailing_zeros().try_into().unwrap();
                self.grid.cell_mut(up_cell).extension.clear();
                self.grid.fill_from_lower_cell(
                    up_cell,
                    CellPosition { row, col: nibble },
                    depth,
                    &self.current_key[up_depth..],
                    nibble,
                );
                // Delete if it existed
                if self.branch_before[row] {
                    let mut bitmap_buf = Vec::with_capacity(2 + 2);
                    bitmap_buf.extend_from_slice(&self.touch_map[row].to_be_bytes()); // touch_map
                    bitmap_buf.extend_from_slice(&0_u16.to_be_bytes()); // after_map
                    branch_data = Some(bitmap_buf);
                }
                self.active_rows -= 1;

                self.current_key.truncate(up_depth.saturating_sub(1));
            }
            _ => {
                // Branch node
                if self.touch_map[row] != 0 {
                    // any modifications
                    if row == 0 {
                        self.root_touched = true
                    } else {
                        // Modification is propagated upwards
                        self.touch_map[row - 1] |= 1_u16 << col;
                    }
                }
                let mut bitmap = self.touch_map[row] & self.after_map[row];
                if !self.branch_before[row] {
                    // There was no branch node before, so we need to touch even the singular child that existed
                    self.touch_map[row] |= self.after_map[row];
                    bitmap |= self.after_map[row];
                }
                // Calculate total length of all hashes
                let mut total_branch_len = 17 - parts_count as usize; // for every empty cell, one byte
                {
                    let mut bitset = self.after_map[row];
                    while bitset != 0 {
                        let bit = bitset & 0_u16.overflowing_sub(bitset).0;
                        let nibble = bit.trailing_zeros() as usize;
                        total_branch_len += self
                            .grid
                            .cell_mut(Some(CellPosition { row, col: nibble }))
                            .compute_hash_len(depth);
                        bitset ^= bit;
                    }
                }
                let branch_data = branch_data.get_or_insert_with(Vec::new);
                branch_data.extend_from_slice(&self.touch_map[row].to_be_bytes());
                branch_data.extend_from_slice(&self.after_map[row].to_be_bytes());

                let mut hasher = Keccak256::new();
                hasher.update(&rlputil::generate_struct_len(total_branch_len));

                let mut last_nibble = 0;
                {
                    let mut bitset = self.after_map[row];
                    while bitset != 0 {
                        let bit = bitset & 0_u16.overflowing_sub(bitset).0;
                        let nibble = bit.trailing_zeros() as usize;
                        for i in last_nibble..nibble {
                            hasher.update(&[0x80]);
                            trace!("{}: empty({},{})", i, row, i);
                        }
                        last_nibble = nibble + 1;
                        let cell_pos = CellPosition { row, col: nibble };
                        {
                            let cell_hash = self.compute_cell_hash(Some(cell_pos), depth);
                            trace!(
                                "{}: computeCellHash({},{},depth={})=[{:?}]",
                                nibble,
                                row,
                                nibble,
                                depth,
                                cell_hash
                            );
                            hasher.update(cell_hash);
                        }

                        if bitmap & bit != 0 {
                            let mut field_bits = 0_u8;

                            let cell = self.grid.grid_cell_mut(cell_pos);
                            if !cell.extension.is_empty() && cell.spk.is_some() {
                                field_bits |= HASHEDKEY_PART;
                            }
                            if cell.apk.is_some() {
                                field_bits |= ACCOUNT_PLAIN_PART;
                            }
                            if cell.spk.is_some() {
                                field_bits |= STORAGE_PLAIN_PART;
                            }
                            if cell.h.is_some() {
                                field_bits |= HASH_PART;
                            }

                            branch_data.push(field_bits);

                            if !cell.extension.is_empty() && cell.spk.is_some() {
                                encode_slice(branch_data, &*cell.extension);
                            }
                            if let Some(apk) = cell.apk {
                                encode_slice(branch_data, &apk.0);
                            }
                            if let Some((addr, location)) = cell.spk {
                                let mut spk = [0; H160::len_bytes() + H256::len_bytes()];
                                spk[..H160::len_bytes()].copy_from_slice(&addr.0);
                                spk[H160::len_bytes()..].copy_from_slice(&location.0);
                                encode_slice(branch_data, &spk);
                            }
                            if let Some(h) = cell.h {
                                encode_slice(branch_data, &h.0);
                            }
                        }

                        bitset ^= bit;
                    }
                }

                {
                    let mut i = last_nibble;
                    while i < 17 {
                        hasher.update(&[0x80]);
                        trace!("{:02x}: empty({},{:02x})", i, row, i);

                        i += 1;
                    }
                }

                let up_cell = self.grid.cell_mut(up_cell);
                up_cell.extension.truncate(depth - up_depth - 1);
                if !up_cell.extension.is_empty() {
                    //// ?
                    up_cell.extension.clear();
                    up_cell
                        .extension
                        .try_extend_from_slice(&self.current_key[up_depth..])
                        .unwrap();
                }
                if depth < 64 {
                    up_cell.apk = None;
                }
                up_cell.spk = None;

                {
                    let h = H256::from_slice(&hasher.finalize()[..]);
                    trace!("}} [{:?}]", h);
                    up_cell.h = Some(h);
                }

                self.active_rows -= 1;

                self.current_key.truncate(up_depth.saturating_sub(1));
            }
        }
        if let Some(branch_data) = branch_data.as_mut() {
            trace!(
                "fold: update key: {}, branch_data: [{}]",
                hex::encode(compact_to_hex(&update_key)),
                hex::encode(&branch_data)
            );
        }
        (branch_data, update_key)
    }
}

type PartFlags = u8;

const HASHEDKEY_PART: PartFlags = 1;
const ACCOUNT_PLAIN_PART: PartFlags = 2;
const STORAGE_PLAIN_PART: PartFlags = 4;
const HASH_PART: PartFlags = 8;

type UpdateFlags = u8;

const CODE_UPDATE: UpdateFlags = 1;
const DELETE_UPDATE: UpdateFlags = 2;
const BALANCE_UPDATE: UpdateFlags = 4;
const NONCE_UPDATE: UpdateFlags = 8;
const STORAGE_UPDATE: UpdateFlags = 16;

fn make_compact_zero_byte(key: &[u8]) -> (u8, usize, usize) {
    let mut compact_zero_byte = 0_u8;
    let mut key_pos = 0_usize;
    let mut key_len = key.len();
    if has_term(key) {
        key_len -= 1;
        compact_zero_byte = 0x20;
    }
    let first_nibble = key.first().copied().unwrap_or(0);
    if key_len & 1 == 1 {
        compact_zero_byte |= 0x10 | first_nibble; // Odd: (1<<4) + first nibble
        key_pos += 1
    }

    (compact_zero_byte, key_pos, key_len)
}

fn has_term(s: &[u8]) -> bool {
    s.last().map(|&v| v == 16).unwrap_or(false)
}

/// Combines two branchData, number 2 coming after (and potentially shadowing) number 1
fn merge_hex_branches(branch_data1: &[u8], branch_data2: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut out = vec![];

    let touch_map1 = u16::from_be_bytes(*array_ref!(branch_data1, 0, 2));
    let after_map1 = u16::from_be_bytes(*array_ref!(branch_data1, 2, 2));
    let bitmap1 = touch_map1 & after_map1;
    let mut pos1 = 4;
    let touch_map2 = u16::from_be_bytes(*array_ref!(branch_data2, 0, 2));
    let after_map2 = u16::from_be_bytes(*array_ref!(branch_data2, 2, 2));
    let bitmap2 = touch_map2 & after_map2;
    let mut pos2 = 4;

    out.extend_from_slice(&(touch_map1 | touch_map2).to_be_bytes());
    out.extend_from_slice(&after_map2.to_be_bytes());

    {
        let mut bitset = bitmap1 | bitmap2;
        while bitset != 0 {
            let bit = bitset & 0_u16.overflowing_sub(bitset).0;
            if bitmap2 & bit != 0 {
                // Add fields from branchData2
                let field_bits = branch_data2[pos2];
                out.push(field_bits);
                pos2 += 1;
                let mut i = 0;
                while i < field_bits.count_ones() {
                    let (l, n) = uvarint(&branch_data2[pos2..])
                        .ok_or_else(|| format_err!("MergeHexBranches value2 overflow for field"))?;
                    if n == 0 {
                        bail!("MergeHexBranches buffer2 too small for field");
                    }
                    out.extend_from_slice(&branch_data2[pos2..pos2 + n]);
                    pos2 += n;

                    let l = l as usize;
                    if branch_data2.len() < pos2 + l {
                        bail!("MergeHexBranches buffer2 too small for field");
                    }
                    if l > 0 {
                        out.extend_from_slice(&branch_data2[pos2..pos2 + l]);
                        pos2 += l;
                    }
                    i += 1;
                }
            }
            if bitmap1 & bit != 0 {
                let add = (touch_map2 & bit == 0) && (after_map2 & bit != 0); // Add fields from branchData1
                let field_bits = branch_data1[pos1];
                if add {
                    out.push(field_bits);
                }
                pos1 += 1;
                let mut i = 0;
                while i < field_bits.count_ones() {
                    let (l, n) = uvarint(&branch_data1[pos1..])
                        .ok_or_else(|| format_err!("value1 overflow for field"))?;
                    if n == 0 {
                        bail!("MergeHexBranches buffer1 too small for field");
                    }
                    if add {
                        out.extend_from_slice(&branch_data1[pos1..pos1 + n]);
                    }
                    pos1 += n;

                    let l = l as usize;
                    if branch_data1.len() < pos1 + l {
                        bail!("MergeHexBranches buffer1 too small for field");
                    }
                    if l > 0 {
                        if add {
                            out.extend_from_slice(&branch_data1[pos1..pos1 + l]);
                        }
                        pos1 += l;
                    }
                    i += 1;
                }
            }
            bitset ^= bit;
        }
    }

    Ok(out)
}

fn hex_to_compact(key: &[u8]) -> Vec<u8> {
    let (zero_byte, key_pos, key_len) = make_compact_zero_byte(key);
    let buf_len = key_len / 2 + 1; // always > 0
    let mut buf = vec![0; buf_len];
    buf[0] = zero_byte;

    let key = &key[..key_pos];
    let mut key_len = key.len();
    if has_term(key) {
        key_len -= 1;
    }

    let mut key_index = 0;
    let mut buf_index = 1;
    while key_index < key_len {
        key_index += 2;
        buf_index += 1;

        if key_index == key_len - 1 {
            buf[buf_index] &= 0x0f
        } else {
            buf[buf_index] = key[key_index + 1]
        }
        buf[buf_index] |= key[key_index] << 4
    }

    buf
}

fn account_leaf_hash_with_key(key: &[u8], val: impl RlpSerializable) -> ArrayVec<u8, 33> {
    // Write key
    let (compact_len, (compact0, ni)) = if has_term(key) {
        (
            (key.len() - 1) / 2 + 1,
            if key.len() & 1 == 0 {
                (
                    48 + key[0], // Odd (1<<4) + first nibble
                    1,
                )
            } else {
                (32, 0)
            },
        )
    } else {
        (
            key.len() / 2 + 1,
            if key.len() & 1 == 1 {
                (
                    16 + key[0], // Odd (1<<4) + first nibble
                    1,
                )
            } else {
                (0, 0)
            },
        )
    };
    // Compute the total length of binary representation
    let (kp, kl) = if compact_len > 1 {
        (Some(0x80 + compact_len as u8), compact_len)
    } else {
        (None, 1)
    };
    complete_leaf_hash(kp, kl, compact_len, key, compact0, ni, val, true)
}

fn extension_hash(key: &[u8], hash: H256) -> H256 {
    // Compute the total length of binary representation
    // Write key
    let (compact_len, (compact0, mut ni)) = if has_term(key) {
        (
            (key.len() - 1) / 2 + 1,
            if key.len() & 1 == 0 {
                (
                    0x30 + key[0], // Odd: (3<<4) + first nibble
                    1,
                )
            } else {
                (0x20, 0)
            },
        )
    } else {
        (
            key.len() / 2 + 1,
            if key.len() & 1 == 1 {
                (
                    0x10 + key[0], // Odd: (1<<4) + first nibble
                    1,
                )
            } else {
                (0, 0)
            },
        )
    };
    let (kp, kl) = if compact_len > 1 {
        (Some(0x80 + compact_len as u8), compact_len)
    } else {
        (None, 1)
    };
    let total_len = if kp.is_some() { 1 } else { 0 } + kl + 33;

    let mut hasher = Keccak256::new();
    hasher.update(&generate_struct_len(total_len));
    if let Some(kp) = kp {
        hasher.update(&[kp]);
    }
    hasher.update(&[compact0]);
    if compact_len > 1 {
        for _ in 1..compact_len {
            hasher.update(&[key[ni] * 16 + key[ni + 1]]);
            ni += 2
        }
    }
    hasher.update(&[0x80 + KECCAK_LENGTH as u8]);
    hasher.update(&hash[..]);
    // Replace previous hash with the new one
    H256::from_slice(&hasher.finalize())
}

fn complete_leaf_hash(
    kp: Option<u8>,
    kl: usize,
    compact_len: usize,
    key: &[u8],
    compact0: u8,
    mut ni: usize,
    val: impl rlputil::RlpSerializable,
    singleton: bool,
) -> ArrayVec<u8, 33> {
    let total_len = if kp.is_some() { 1 } else { 0 } + kl + val.double_rlp_len();
    let len_prefix = generate_struct_len(total_len);
    let embedded = !singleton && total_len + len_prefix.len() < KECCAK_LENGTH;

    let mut buf = ArrayVec::new();
    if embedded {
        buf.try_extend_from_slice(&len_prefix).unwrap();
        if let Some(kp) = kp {
            buf.push(kp);
        }
        buf.push(compact0);
        for _ in 1..compact_len {
            buf.push(key[ni] * 16 + key[ni + 1]);
            ni += 2
        }
        let mut b = buf.writer();
        val.to_double_rlp(&mut b);
    } else {
        let mut hasher = Keccak256::new();
        hasher.update(&len_prefix);
        if let Some(kp) = kp {
            hasher.update(&[kp]);
        }
        hasher.update(&[compact0]);
        for _ in 1..compact_len {
            hasher.update(&[key[ni] * 16 + key[ni + 1]]);
            ni += 2;
        }
        val.to_double_rlp(&mut hasher);
        buf.push(0x80 + KECCAK_LENGTH as u8);
        buf.try_extend_from_slice(&hasher.finalize()[..]).unwrap();
    }

    buf
}

fn leaf_hash_with_key_val(
    key: &[u8],
    val: rlputil::RlpSerializableBytes<'_>,
    singleton: bool,
) -> ArrayVec<u8, 33> {
    // Compute the total length of binary representation
    // Write key
    let compact_len = key.len() / 2 + 1;
    let (compact0, ni) = if key.len() & 1 == 0 {
        (0x30 + key[0], 1) // Odd: (3<<4) + first nibble
    } else {
        (0x20, 0)
    };
    let (kp, kl) = if compact_len > 1 {
        (Some(0x80 + compact_len as u8), compact_len)
    } else {
        (None, 1)
    };
    complete_leaf_hash(kp, kl, compact_len, key, compact0, ni, val, singleton)
}

fn compact_to_hex(compact: &[u8]) -> Vec<u8> {
    if compact.is_empty() {
        return vec![];
    }
    let mut base = keybytes_to_hex(compact);
    // delete terminator flag
    if base[0] < 2 {
        base.truncate(base.len() - 1);
    }
    // apply odd flag
    let chop = (2 - base[0] as usize) & 1;
    base[chop..].to_vec()
}

fn keybytes_to_hex(s: &[u8]) -> Vec<u8> {
    let l = s.len() * 2 + 1;
    let mut nibbles = Vec::with_capacity(l);
    for (i, b) in s.iter().copied().enumerate() {
        nibbles[i * 2] = b / 16;
        nibbles[i * 2 + 1] = b % 16;
    }
    nibbles[l - 1] = 16;
    nibbles
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;
    use std::collections::hash_map::Entry;

    struct MockState {
        /// Backbone of the state
        sm: HashMap<Vec<u8>, Vec<u8>>,
        /// Backbone of the commitments
        cm: HashMap<Vec<u8>, Vec<u8>>,
    }

    impl MockState {
        fn execute(
            &mut self,
            i: StartedInterrupt<HashMap<Vec<u8>, Vec<u8>>>,
        ) -> HashMap<Vec<u8>, Vec<u8>> {
            let mut interrupt = i.resume();

            loop {
                interrupt = match interrupt {
                    Interrupt::LoadBranch { interrupt, prefix } => interrupt.resume({
                        BranchData(self.cm.get(&prefix).map(|v| {
                            v[2..] // Skip touchMap, but keep afterMap
                                .to_vec()
                        }))
                    }),
                    Interrupt::LoadAccount {
                        interrupt,
                        plain_key,
                        mut cell,
                    } => interrupt.resume({
                        let ex_bytes = &self.sm[&plain_key];

                        let (ex, pos) = Update::decode(ex_bytes, 0).unwrap();

                        assert_eq!(
                            pos,
                            ex_bytes.len(),
                            "accountFn key [{}] leftover bytes in [{}], consumed {:02x}",
                            hex::encode(plain_key),
                            hex::encode(ex_bytes),
                            pos
                        );
                        assert_eq!(
                            ex.flags & STORAGE_UPDATE,
                            0,
                            "accountFn reading storage item for key [{}]",
                            hex::encode(&plain_key)
                        );
                        assert_eq!(
                            ex.flags & DELETE_UPDATE,
                            0,
                            "accountFn reading deleted account for key [{}]",
                            hex::encode(&plain_key)
                        );
                        if ex.flags & BALANCE_UPDATE != 0 {
                            cell.balance = ex.balance;
                        } else {
                            cell.balance = U256::ZERO;
                        }
                        if ex.flags & NONCE_UPDATE != 0 {
                            cell.nonce = ex.nonce;
                        } else {
                            cell.nonce = 0;
                        }
                        if ex.flags & CODE_UPDATE != 0 {
                            cell.code_hash[..].copy_from_slice(&ex.code_hash_or_storage[..]);
                        } else {
                            cell.code_hash = EMPTY_HASH;
                        }

                        FilledAccount(cell)
                    }),
                    Interrupt::LoadStorage {
                        interrupt,
                        plain_key,
                        mut cell,
                    } => interrupt.resume({
                        let ex_bytes = &self.sm[&plain_key];

                        let (ex, pos) = Update::decode(ex_bytes, 0)
                            .with_context(|| {
                                format!(
                                    "storage decode existing [{}], bytes: [{}]",
                                    hex::encode(&plain_key),
                                    hex::encode(&ex_bytes)
                                )
                            })
                            .unwrap();
                        assert_eq!(
                            pos,
                            ex_bytes.len(),
                            "storageFn key [{}] leftover bytes in [{}], comsumed {:02x}",
                            hex::encode(&plain_key),
                            hex::encode(ex_bytes),
                            pos
                        );
                        assert_eq!(
                            ex.flags & BALANCE_UPDATE,
                            0,
                            "storageFn reading balance for key [{}]",
                            hex::encode(plain_key)
                        );
                        assert_eq!(
                            ex.flags & NONCE_UPDATE,
                            0,
                            "storageFn reading nonce for key [{}]",
                            hex::encode(plain_key)
                        );
                        assert_eq!(
                            ex.flags & CODE_UPDATE,
                            0,
                            "storageFn reading code hash for key [{}]",
                            hex::encode(plain_key)
                        );
                        assert_eq!(
                            ex.flags & DELETE_UPDATE,
                            0,
                            "storageFn reading deleted item for key [{}]",
                            hex::encode(plain_key)
                        );
                        if ex.flags & STORAGE_UPDATE != 0 {
                            cell.storage = Some(U256::from_be_bytes(static_left_pad(
                                &ex.code_hash_or_storage,
                            )));
                        } else {
                            cell.storage = None;
                        }
                        FilledStorage(cell)
                    }),
                    Interrupt::BranchUpdate { .. } => unreachable!(),
                    Interrupt::Complete { result, .. } => return result,
                }
            }
        }

        fn apply_plain_updates(
            &mut self,
            plain_keys: Vec<Vec<u8>>,
            updates: Vec<Update>,
        ) -> anyhow::Result<()> {
            for (key, update) in plain_keys.into_iter().zip(updates) {
                if update.flags & DELETE_UPDATE != 0 {
                    self.sm.remove(&key);
                } else {
                    match self.sm.entry(key.clone()) {
                        Entry::Occupied(mut entry) => {
                            let ex_bytes = entry.get();
                            let (mut ex, pos) = Update::decode(ex_bytes, 0).with_context(|| {
                                format!(
                                    "applyPlainUpdates decode existing [{}], bytes: [{}]",
                                    hex::encode(&key),
                                    hex::encode(ex_bytes)
                                )
                            })?;
                            if pos != ex_bytes.len() {
                                bail!("applyPlainUpdates key [{}] leftover bytes in [{}], comsumed {}", hex::encode(&key), hex::encode(ex_bytes), pos);
                            }
                            if update.flags & BALANCE_UPDATE != 0 {
                                ex.flags |= BALANCE_UPDATE;
                                ex.balance = update.balance;
                            }
                            if update.flags & NONCE_UPDATE != 0 {
                                ex.flags |= NONCE_UPDATE;
                                ex.nonce = update.nonce;
                            }
                            if update.flags & CODE_UPDATE != 0 || update.flags & STORAGE_UPDATE != 0
                            {
                                if update.flags & CODE_UPDATE != 0 {
                                    ex.flags |= CODE_UPDATE;
                                }
                                if update.flags & STORAGE_UPDATE != 0 {
                                    ex.flags |= STORAGE_UPDATE;
                                }

                                ex.code_hash_or_storage = update.code_hash_or_storage;
                            }
                            entry.insert(ex.encode());
                        }
                        Entry::Vacant(entry) => {
                            entry.insert(update.encode());
                        }
                    }
                }
            }

            Ok(())
        }

        fn apply_branch_node_updates(&mut self, updates: HashMap<Vec<u8>, Vec<u8>>) {
            for (key, update) in updates {
                match self.cm.entry(key) {
                    Entry::Occupied(mut pre) => {
                        pre.insert(merge_hex_branches(pre.get(), &update).unwrap());
                    }
                    Entry::Vacant(entry) => {
                        entry.insert(update);
                    }
                }
            }
        }
    }
}
