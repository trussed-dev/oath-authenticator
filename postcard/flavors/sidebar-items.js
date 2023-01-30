window.SIDEBAR_ITEMS = {"struct":[["Cobs","The `Cobs` flavor implements Consistent Overhead Byte Stuffing on the serialized data. The output of this flavor includes the termination/sentinel byte of `0x00`."],["HVec","The `HVec` flavor is a wrapper type around a `heapless::Vec`. This is a stack allocated data structure, with a fixed maximum size and variable amount of contents."],["Slice","The `Slice` flavor is a storage flavor, storing the serialized (or otherwise modified) bytes into a plain `[u8]` slice. The `Slice` flavor resolves into a sub-slice of the original slice buffer."]],"trait":[["SerFlavor","The SerFlavor trait acts as a combinator/middleware interface that can be used to pass bytes through storage or modification flavors. See the module level documentation for more information and examples."]]};