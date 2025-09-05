use halo2_proofs::poly;
use pasta_curves::pallas::Affine;
use std::borrow::Borrow;
use std::collections::BTreeSet;
use std::io::BufReader;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::sync::OnceLock;

const PARAMS_FILES: [&[u8]; 16] = [
    include_bytes!("../params/params_k1.bin"),
    include_bytes!("../params/params_k2.bin"),
    include_bytes!("../params/params_k3.bin"),
    include_bytes!("../params/params_k4.bin"),
    include_bytes!("../params/params_k5.bin"),
    include_bytes!("../params/params_k6.bin"),
    include_bytes!("../params/params_k7.bin"),
    include_bytes!("../params/params_k8.bin"),
    include_bytes!("../params/params_k9.bin"),
    include_bytes!("../params/params_k10.bin"),
    include_bytes!("../params/params_k11.bin"),
    include_bytes!("../params/params_k12.bin"),
    include_bytes!("../params/params_k13.bin"),
    include_bytes!("../params/params_k14.bin"),
    include_bytes!("../params/params_k15.bin"),
    include_bytes!("../params/params_k16.bin"),
];

#[derive(Debug, Clone)]
struct LazyParams {
    k: u32,
    params: Arc<OnceLock<Arc<poly::commitment::Params<Affine>>>>,
}

impl LazyParams {
    fn new(k: u32) -> Self {
        Self {
            k,
            params: Arc::new(OnceLock::default()),
        }
    }

    fn load(&self) -> Arc<poly::commitment::Params<Affine>> {
        let mut reader = BufReader::new(PARAMS_FILES[(self.k - 1) as usize]);
        Arc::new(poly::commitment::Params::read(&mut reader).unwrap())
    }

    fn get(&self) -> Arc<poly::commitment::Params<Affine>> {
        self.params.get_or_init(|| self.load()).clone()
    }
}

impl PartialEq for LazyParams {
    fn eq(&self, other: &Self) -> bool {
        self.k == other.k
    }
}

impl Eq for LazyParams {}

impl Ord for LazyParams {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.k.cmp(&other.k)
    }
}

impl PartialOrd for LazyParams {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Borrow<u32> for LazyParams {
    fn borrow(&self) -> &u32 {
        &self.k
    }
}

#[derive(Debug, Default)]
pub struct Cache {
    params: Mutex<BTreeSet<LazyParams>>,
}

impl Cache {
    fn lookup(&self, k: u32) -> LazyParams {
        let mut params = self.params.lock().unwrap();
        // TODO: replace with `get_or_insert` (https://github.com/rust-lang/rust/issues/133549).
        match params.get(&k) {
            Some(params) => params.clone(),
            None => {
                let new = LazyParams::new(k);
                params.insert(new.clone());
                new
            }
        }
    }

    pub fn get(&self, k: u32) -> Arc<poly::commitment::Params<Affine>> {
        self.lookup(k).get().clone()
    }
}

pub static CACHE: LazyLock<Cache> = LazyLock::new(Cache::default);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smoke() {
        // We can't really test this cache. A smoke test is the best we can do.
        CACHE.get(5);
    }
}
