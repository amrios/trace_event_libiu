use core::marker::PhantomData;
use core::mem::size_of;

#[repr(C)]
pub struct IUMap<K, V> {
    map_type: u32,
    key_size: u32,
    val_size: u32,
    max_size: u32,
    map_flag: u32,
    key_type: PhantomData<K>,
    val_type: PhantomData<V>,
}

impl<K, V> IUMap<K, V> {
    pub const fn new(mt: u32, ms: u32, mf: u32) -> IUMap<K, V> {
        Self {
            map_type: mt,
            key_size: size_of::<K>() as u32,
            val_size: size_of::<V>() as u32,
            max_size: ms,
            map_flag: mf,
            key_type: PhantomData,
            val_type: PhantomData,
        }
    }
}

#[macro_export]
macro_rules! MAP_DEF {
    ($n:ident, $in:ident, $k:ty, $v:ty, $mt:expr, $ms:expr, $mf:expr) => {
        #[no_mangle]
        #[used]
        #[link_section = ".maps"]
        static $in: IUMap<$k, $v> = IUMap::new($mt, $ms, $mf);

        #[no_mangle]
        #[used]
        #[link_section = ".maps"]
        static $n: &IUMap<$k, $v> = &$in;
    };
}
