tox-capi [![Build Status](https://travis-ci.org/quininer/tox-capi.svg?branch=master)](https://travis-ci.org/quininer/tox-capi)
--------

C API for [zetox], a [toxcore] implementation in Rust.
Aims to be compatible with C toxcore.

Powered by [rusty-cheddar].


## Dependencies
| **Name** | **Version** |
|----------|-------------|
| libsodium | >=1.0.0 |


## Building
Fairly simple. You'll need [Rust] and [libsodium].

When you'll have deps, build debug version with
```bash
make
```

## License

Licensed under GPLv3+. For details, see [LICENSE](/LICENSE).

[libsodium]: https://github.com/jedisct1/libsodium
[Rust]: https://www.rust-lang.org/
[rusty-cheddar]: https://github.com/Sean1708/rusty-cheddar
[toxcore]: https://github.com/irungentoo/toxcore
[zetox]: https://github.com/zetok/tox
