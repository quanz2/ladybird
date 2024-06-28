#!/usr/bin/env bash

set -e

ARG0=$0
print_help() {
    NAME=$(basename "$ARG0")
    cat <<EOF
Usage: $NAME COMMAND [ARGS...]
  Supported COMMANDs:
    build:      Compiles the target binaries, [ARGS...] are passed through to ninja
    install:    Installs the target binary
    run:        $NAME run EXECUTABLE [ARGS...]
                    Runs the EXECUTABLE on the build host, e.g.
                    'shell' or 'js', [ARGS...] are passed through to the executable
    gdb:        Same as run, but also starts a gdb remote session.
                $NAME gdb EXECUTABLE [-ex 'any gdb command']...
                    Passes through '-ex' commands to gdb
    vcpkg:      Ensure that dependencies are available
    test:       $NAME test [TEST_NAME_PATTERN]
                    Runs the unit tests on the build host, or if TEST_NAME_PATTERN
                    is specified tests matching it.
    delete:     Removes the build environment
    rebuild:    Deletes and re-creates the build environment, and compiles the project
    addr2line:  $NAME addr2line BINARY_FILE ADDRESS
                    Resolves the ADDRESS in BINARY_FILE to a file:line. It will
                    attempt to find the BINARY_FILE in the appropriate build directory

  Examples:
    $NAME run ladybird
        Runs the Ladybird browser
    $NAME run js -A
        Runs the js(1) REPL
    $NAME test
        Runs the unit tests on the build host
    $NAME addr2line RequestServer 0x12345678
        Resolves the address 0x12345678 in the RequestServer binary
EOF
}

usage() {
    >&2 print_help
    exit 1
}

CMD=$1
[ -n "$CMD" ] || usage
shift
if [ "$CMD" = "help" ]; then
    print_help
    exit 0
fi

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# shellcheck source=/dev/null
. "${DIR}/shell_include.sh"

exit_if_running_as_root "Do not run ladybird.sh as root, your Build directory will become root-owned"

# shellcheck source=/dev/null
. "${DIR}/find_compiler.sh"

CMAKE_ARGS=()
CMD_ARGS=( "$@" )

get_top_dir() {
    git rev-parse --show-toplevel
}

create_build_dir() {
    cmake --preset default "${CMAKE_ARGS[@]}" -S "$LADYBIRD_SOURCE_DIR" -B "$BUILD_DIR"
}

cmd_with_target() {
    pick_host_compiler
    CMAKE_ARGS+=("-DCMAKE_C_COMPILER=${CC}")
    CMAKE_ARGS+=("-DCMAKE_CXX_COMPILER=${CXX}")

    if [ ! -d "$LADYBIRD_SOURCE_DIR" ]; then
        LADYBIRD_SOURCE_DIR="$(get_top_dir)"
        export LADYBIRD_SOURCE_DIR
    fi
    BUILD_DIR="$LADYBIRD_SOURCE_DIR/Build/ladybird"
    CMAKE_ARGS+=("-DCMAKE_INSTALL_PREFIX=$LADYBIRD_SOURCE_DIR/Build/ladybird-install")

    export PATH="$LADYBIRD_SOURCE_DIR/Toolchain/Local/cmake/bin:$LADYBIRD_SOURCE_DIR/Toolchain/Local/vcpkg/bin:$PATH"
    export VCPKG_ROOT="$LADYBIRD_SOURCE_DIR/Toolchain/Tarballs/vcpkg"
}

ensure_target() {
    [ -f "$BUILD_DIR/build.ninja" ] || create_build_dir
}

run_tests() {
    local TEST_NAME="$1"
    local CTEST_ARGS=("--preset" "default" "--output-on-failure" "--test-dir" "$BUILD_DIR")
    if [ -n "$TEST_NAME" ]; then
        if [ "$TEST_NAME" = "WPT" ]; then
            CTEST_ARGS+=("-C" "Integration")
        fi
        CTEST_ARGS+=("-R" "$TEST_NAME")
    fi
    ctest "${CTEST_ARGS[@]}"
}

build_target() {
    # Get either the environment MAKEJOBS or all processors via CMake
    [ -z "$MAKEJOBS" ] && MAKEJOBS=$(cmake -P "$LADYBIRD_SOURCE_DIR/Meta/CMake/processor-count.cmake")

    # With zero args, we are doing a standard "build"
    # With multiple args, we are doing an install/run
    if [ $# -eq 0 ]; then
        CMAKE_BUILD_PARALLEL_LEVEL="$MAKEJOBS" cmake --build "$BUILD_DIR"
    else
        ninja -j "$MAKEJOBS" -C "$BUILD_DIR" -- "$@"
    fi
}

delete_target() {
    [ ! -d "$BUILD_DIR" ] || rm -rf "$BUILD_DIR"
}

build_cmake() {
    echo "CMake version too old: build_cmake"
    ( cd "$LADYBIRD_SOURCE_DIR/Toolchain" && ./BuildCMake.sh )
}

build_vcpkg() {
    ( cd "$LADYBIRD_SOURCE_DIR/Toolchain" && ./BuildVcpkg.sh )
}

ensure_toolchain() {
    if [ "$(cmake -P "$LADYBIRD_SOURCE_DIR"/Meta/CMake/cmake-version.cmake)" -ne 1 ]; then
        build_cmake
    fi
{
    "name": "Ladybird Development",
    "id": "ladybird",
    "version": "2.0.0",
    "description": "Enable development of Ladybird libraries and applications",
    "options": {
        "llvm_version": {
            "type": "string",
            "proposals": [
                17,
                18,
                "trunk"
            ],
            "default": 18,
            "description": "Select LLVM compiler version to use"
        }
    }
}
    build_vcpkg
}

run_gdb() {
    local GDB_ARGS=()
    local PASS_ARG_TO_GDB=""
    local LAGOM_EXECUTABLE=""
    for arg in "${CMD_ARGS[@]}"; do
        if [ "$PASS_ARG_TO_GDB" != "" ]; then
            GDB_ARGS+=( "$PASS_ARG_TO_GDB" "$arg" )

            PASS_ARG_TO_GDB=""
        elif [ "$arg" = "-ex" ]; then
            PASS_ARG_TO_GDB="$arg"
        elif [[ "$arg" =~ ^-.*$ ]]; then
            die "Don't know how to handle argument: $arg"
        else
            if [ "$LAGOM_EXECUTABLE" != "" ]; then
                die "Lagom executable can't be specified more than once"
            fi
            LAGOM_EXECUTABLE="$arg"
        fi
    done
    if [ "$PASS_ARG_TO_GDB" != "" ]; then
        GDB_ARGS+=( "$PASS_ARG_TO_GDB" )
    fi
    gdb "$BUILD_DIR/bin/$LAGOM_EXECUTABLE" "${GDB_ARGS[@]}"
}

build_and_run_lagom_target() {
    local lagom_target="${CMD_ARGS[0]}"
    local lagom_args=("${CMD_ARGS[@]:1}")

    if [ -z "$lagom_target" ]; then
        lagom_target="ladybird"
    fi
/*
 * Copyright (c) 2020, the SerenityOS developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/Concepts.h>
#include <AK/Find.h>
#include <AK/Iterator.h>

namespace AK {

template<typename TEndIterator, IteratorPairWith<TEndIterator> TIterator>
[[nodiscard]] constexpr bool all_of(
    TIterator const& begin,
    TEndIterator const& end,
    auto const& predicate)
{
    constexpr auto negated_predicate = [](auto const& pred) {
        return [&](auto const& elem) { return !pred(elem); };
    };
    return !(find_if(begin, end, negated_predicate(predicate)) != end);
}

template<IterableContainer Container>
[[nodiscard]] constexpr bool all_of(Container&& container, auto const& predicate)
{
    return all_of(container.begin(), container.end(), predicate);
}

}

#if USING_AK_GLOBALLY
using AK::all_of;
#endif
    build_target "${lagom_target}"

    if [ "$lagom_target" = "ladybird" ] && [ "$(uname -s)" = "Darwin" ]; then
        open --wait-apps --stdout "$(tty)" --stderr "$(tty)" "$BUILD_DIR/bin/Ladybird.app" --args "${lagom_args[@]}"
    else
        local lagom_bin="$lagom_target"
        if [ "$lagom_bin" = "ladybird" ]; then
            lagom_bin="Ladybird"
        fi
        "$BUILD_DIR/bin/$lagom_bin" "${lagom_args[@]}"
    fi
}

if [[ "$CMD" =~ ^(build|install|run|gdb|test|rebuild|recreate|addr2line)$ ]]; then
    cmd_with_target
    [[ "$CMD" != "recreate" && "$CMD" != "rebuild" ]] || delete_target
    ensure_toolchain
    ensure_target
    case "$CMD" in
        build)
            build_target "${CMD_ARGS[@]}"
            ;;
        install)
            build_target
            build_target install
            ;;
        run)
            build_and_run_lagom_target
            ;;
        gdb)
          [ $# -ge 1 ] || usage
          build_target "${CMD_ARGS[@]}"
          run_gdb "${CMD_ARGS[@]}"
          ;;
        test)
            build_target
            run_tests "${CMD_ARGS[0]}"
            ;;
        rebuild)
            build_target "${CMD_ARGS[@]}"
            ;;
        recreate)
            ;;
        addr2line)
            build_target
            [ $# -ge 2 ] || usage
            BINARY_FILE="$1"; shift
            BINARY_FILE_PATH="$BUILD_DIR/$BINARY_FILE"
            command -v addr2line >/dev/null 2>&1 || die "Please install addr2line!"
            ADDR2LINE=addr2line
            if [ -x "$BINARY_FILE_PATH" ]; then
                "$ADDR2LINE" -e "$BINARY_FILE_PATH" "$@"
            else
                find "$BUILD_DIR" -name "$BINARY_FILE" -executable -type f -exec "$ADDR2LINE" -e {} "$@" \;
            fi
            ;;
        *)
            build_target "$CMD" "${CMD_ARGS[@]}"
            ;;
    esac
elif [ "$CMD" = "delete" ]; then
    cmd_with_target
    delete_target
elif [ "$CMD" = "vcpkg" ]; then
    cmd_with_target
    ensure_toolchain
else
    >&2 echo "Unknown command: $CMD"
    usage
fi
/*
 * Copyright (c) 2021, kleines Filmröllchen <filmroellchen@serenityos.org>.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/ByteBuffer.h>
#include <AK/Concepts.h>
#include <AK/MaybeOwned.h>
#include <AK/NumericLimits.h>
#include <AK/OwnPtr.h>
#include <AK/Stream.h>

namespace AK {

/// A stream wrapper class that allows you to read arbitrary amounts of bits
/// in big-endian order from another stream.
class BigEndianInputBitStream : public Stream {
public:
    explicit BigEndianInputBitStream(MaybeOwned<Stream> stream)
        : m_stream(move(stream))
    {
    }

    // ^Stream
    virtual ErrorOr<Bytes> read_some(Bytes bytes) override
    {
        if (m_current_byte.has_value() && is_aligned_to_byte_boundary()) {
            bytes[0] = m_current_byte.release_value();
            auto freshly_read_bytes = TRY(m_stream->read_some(bytes.slice(1)));
            return bytes.trim(1 + freshly_read_bytes.size());
        }
        align_to_byte_boundary();
        return m_stream->read_some(bytes);
    }
    virtual ErrorOr<size_t> write_some(ReadonlyBytes bytes) override { return m_stream->write_some(bytes); }
    virtual bool is_eof() const override { return m_stream->is_eof() && !m_current_byte.has_value(); }
    virtual bool is_open() const override { return m_stream->is_open(); }
    virtual void close() override
    {
        m_stream->close();
        align_to_byte_boundary();
    }

    ErrorOr<bool> read_bit()
    {
        return read_bits<bool>(1);
    }

    /// Depending on the number of bits to read, the return type can be chosen appropriately.
    /// This avoids a bunch of static_cast<>'s for the user.
    // TODO: Support u128, u256 etc. as well: The concepts would be quite complex.
    template<Unsigned T = u64>
    ErrorOr<T> read_bits(size_t count)
    {
        if constexpr (IsSame<bool, T>) {
            VERIFY(count == 1);
        }
        T result = 0;

        size_t nread = 0;
        while (nread < count) {
            if (m_current_byte.has_value()) {
                if constexpr (!IsSame<bool, T> && !IsSame<u8, T>) {
                    // read as many bytes as possible directly
                    if (((count - nread) >= 8) && is_aligned_to_byte_boundary()) {
                        // shift existing data over
                        result <<= 8;
                        result |= m_current_byte.value();
                        nread += 8;
                        m_current_byte.clear();
                    } else {
                        auto const bit = (m_current_byte.value() >> (7 - m_bit_offset)) & 1;
                        result <<= 1;
                        result |= bit;
                        ++nread;
                        if (m_bit_offset++ == 7)
                            m_current_byte.clear();
                    }
                } else {
                    // Always take this branch for booleans or u8: there's no purpose in reading more than a single bit
                    auto const bit = (m_current_byte.value() >> (7 - m_bit_offset)) & 1;
                    if constexpr (IsSame<bool, T>)
                        result = bit;
                    else {
                        result <<= 1;
                        result |= bit;
                    }
                    ++nread;
                    if (m_bit_offset++ == 7)
                        m_current_byte.clear();
                }
            } else {
                m_current_byte = TRY(m_stream->read_value<u8>());
                m_bit_offset = 0;
            }
        }

        return result;
    }

    /// Discards any sub-byte stream positioning the input stream may be keeping track of.
    /// Non-bitwise reads will implicitly call this.
    void align_to_byte_boundary()
    {
        m_current_byte.clear();
        m_bit_offset = 0;
    }

    /// Whether we are (accidentally or intentionally) at a byte boundary right now.
    ALWAYS_INLINE bool is_aligned_to_byte_boundary() const { return m_bit_offset % 8 == 0; }
    ALWAYS_INLINE u8 bits_until_next_byte_boundary() const { return m_bit_offset % 8 == 0 ? 0 : 8 - m_bit_offset; }

private:
    Optional<u8> m_current_byte;
    size_t m_bit_offset { 0 };
    MaybeOwned<Stream> m_stream;
};

class LittleEndianBitStream : public Stream {
protected:
    using BufferType = u64;

    static constexpr size_t bits_per_byte = 8u;
    static constexpr size_t bit_buffer_size = sizeof(BufferType) * bits_per_byte;

    explicit LittleEndianBitStream(MaybeOwned<Stream> stream)
        : m_stream(move(stream))
    {
    }

    template<Unsigned T>
    static constexpr T lsb_mask(T bits)
    {
        constexpr auto max = NumericLimits<T>::max();
        constexpr auto digits = NumericLimits<T>::digits();

        return bits == 0 ? 0 : max >> (digits - bits);
    }

    ALWAYS_INLINE bool is_aligned_to_byte_boundary() const { return m_bit_count % bits_per_byte == 0; }

    MaybeOwned<Stream> m_stream;

    BufferType m_bit_buffer { 0 };
    u8 m_bit_count { 0 };
};

/// A stream wrapper class that allows you to read arbitrary amounts of bits
/// in little-endian order from another stream.
class LittleEndianInputBitStream : public LittleEndianBitStream {
public:
    enum UnsatisfiableReadBehavior {
        Reject,
        FillWithZero,
    };

    explicit LittleEndianInputBitStream(MaybeOwned<Stream> stream, UnsatisfiableReadBehavior unsatisfiable_read_behavior = UnsatisfiableReadBehavior::Reject)
        : LittleEndianBitStream(move(stream))
        , m_unsatisfiable_read_behavior(unsatisfiable_read_behavior)
    {
    }

    // ^Stream
    virtual ErrorOr<Bytes> read_some(Bytes bytes) override
    {
        align_to_byte_boundary();

        size_t bytes_read = 0;
        auto buffer = bytes;

        if (m_bit_count > 0) {
            auto bits_to_read = min(buffer.size() * bits_per_byte, m_bit_count);
            auto result = TRY(read_bits(bits_to_read));

            bytes_read = bits_to_read / bits_per_byte;
            buffer.overwrite(0, &result, bytes_read);

            buffer = buffer.slice(bytes_read);
        }

        buffer = TRY(m_stream->read_some(buffer));
        bytes_read += buffer.size();

        return bytes.trim(bytes_read);
    }

    virtual ErrorOr<size_t> write_some(ReadonlyBytes bytes) override { return m_stream->write_some(bytes); }
    virtual bool is_eof() const override { return m_stream->is_eof() && m_bit_count == 0; }
    virtual bool is_open() const override { return m_stream->is_open(); }
    virtual void close() override
    {
        m_stream->close();
        align_to_byte_boundary();
    }

    ErrorOr<bool> read_bit()
    {
        return read_bits<bool>(1);
    }

    /// Depending on the number of bits to read, the return type can be chosen appropriately.
    /// This avoids a bunch of static_cast<>'s for the user.
    // TODO: Support u128, u256 etc. as well: The concepts would be quite complex.
    template<Unsigned T = u64>
    ErrorOr<T> read_bits(size_t count)
    {
        auto result = TRY(peek_bits<T>(count));
        discard_previously_peeked_bits(count);

        return result;
    }

    template<Unsigned T = u64>
    ErrorOr<T> peek_bits(size_t count)
    {
        if (count > m_bit_count)
            TRY(refill_buffer_from_stream(count));

        return m_bit_buffer & lsb_mask<T>(min(count, m_bit_count));
    }

    ALWAYS_INLINE void discard_previously_peeked_bits(u8 count)
    {
        // We allow "retrieving" more bits than we can provide, but we need to make sure that we don't underflow the current bit counter.
        // This only affects certain "modes", but all the relevant checks have been handled in the respective `peek_bits` call.
        if (count > m_bit_count)
            count = m_bit_count;

        m_bit_buffer >>= count;
        m_bit_count -= count;
    }

    /// Discards any sub-byte stream positioning the input stream may be keeping track of.
    /// Non-bitwise reads will implicitly call this.
    u8 align_to_byte_boundary()
    {
        u8 remaining_bits = 0;

        if (auto offset = m_bit_count % bits_per_byte; offset != 0) {
            remaining_bits = m_bit_buffer & lsb_mask<u8>(offset);
            discard_previously_peeked_bits(offset);
        }

        return remaining_bits;
    }

private:
    ErrorOr<void> refill_buffer_from_stream(size_t requested_bit_count)
    {
        while (requested_bit_count > m_bit_count) [[likely]] {
            if (m_stream->is_eof()) [[unlikely]] {
                if (m_unsatisfiable_read_behavior == UnsatisfiableReadBehavior::FillWithZero) {
                    m_bit_count = requested_bit_count;
                    return {};
                }

                return Error::from_string_literal("Reached end-of-stream without collecting the required number of bits");
            }

            size_t bits_to_read = bit_buffer_size - m_bit_count;
            size_t bytes_to_read = bits_to_read / bits_per_byte;

            BufferType buffer = 0;
            auto bytes = TRY(m_stream->read_some({ &buffer, bytes_to_read }));

            m_bit_buffer |= (buffer << m_bit_count);
            m_bit_count += bytes.size() * bits_per_byte;
        }

        return {};
    }

    UnsatisfiableReadBehavior m_unsatisfiable_read_behavior;
};

/// A stream wrapper class that allows you to write arbitrary amounts of bits
/// in big-endian order to another stream.
class BigEndianOutputBitStream : public Stream {
public:
    explicit BigEndianOutputBitStream(MaybeOwned<Stream> stream)
        : m_stream(move(stream))
    {
    }

    virtual ErrorOr<Bytes> read_some(Bytes) override
    {
        return Error::from_errno(EBADF);
    }

    virtual ErrorOr<size_t> write_some(ReadonlyBytes bytes) override
    {
        VERIFY(m_bit_offset == 0);
        return m_stream->write_some(bytes);
    }

    template<Unsigned T>
    ErrorOr<void> write_bits(T value, size_t bit_count)
    {
        VERIFY(m_bit_offset <= 7);

        while (bit_count > 0) {
            u8 next_bit = (value >> (bit_count - 1)) & 1;
            bit_count--;

            m_current_byte <<= 1;
            m_current_byte |= next_bit;
            m_bit_offset++;

            if (m_bit_offset > 7) {
                TRY(m_stream->write_value(m_current_byte));
                m_bit_offset = 0;
                m_current_byte = 0;
            }
        }

        return {};
    }

    virtual bool is_eof() const override
    {
        return true;
    }

    virtual bool is_open() const override
    {
        return m_stream->is_open();
    }

    virtual void close() override
    {
    }

    size_t bit_offset() const
    {
        return m_bit_offset;
    }

    ErrorOr<void> align_to_byte_boundary()
    {
        if (m_bit_offset == 0)
            return {};

        TRY(write_bits(0u, 8 - m_bit_offset));
        VERIFY(m_bit_offset == 0);
        return {};
    }

private:
    MaybeOwned<Stream> m_stream;
    u8 m_current_byte { 0 };
    size_t m_bit_offset { 0 };
};

/// A stream wrapper class that allows you to write arbitrary amounts of bits
/// in little-endian order to another stream.
class LittleEndianOutputBitStream : public LittleEndianBitStream {
public:
    explicit LittleEndianOutputBitStream(MaybeOwned<Stream> stream)
        : LittleEndianBitStream(move(stream))
    {
    }

    virtual ErrorOr<Bytes> read_some(Bytes) override
    {
        return Error::from_errno(EBADF);
    }

    virtual ErrorOr<size_t> write_some(ReadonlyBytes bytes) override
    {
        VERIFY(is_aligned_to_byte_boundary());

        if (m_bit_count > 0)
            TRY(flush_buffer_to_stream());

        return m_stream->write_some(bytes);
    }

    template<Unsigned T>
    ErrorOr<void> write_bits(T value, size_t count)
    {
        if (m_bit_count == bit_buffer_size) {
            TRY(flush_buffer_to_stream());
        } else if (auto remaining = bit_buffer_size - m_bit_count; count >= remaining) {
            m_bit_buffer |= (static_cast<BufferType>(value) & lsb_mask<BufferType>(remaining)) << m_bit_count;
            m_bit_count = bit_buffer_size;

            if (remaining != sizeof(value) * bits_per_byte)
                value >>= remaining;
            count -= remaining;

            TRY(flush_buffer_to_stream());
        }

        if (count == 0)
            return {};

        m_bit_buffer |= static_cast<BufferType>(value) << m_bit_count;
        m_bit_count += count;

        return {};
    }

    ALWAYS_INLINE ErrorOr<void> flush_buffer_to_stream()
    {
        auto bytes_to_write = m_bit_count / bits_per_byte;
        TRY(m_stream->write_until_depleted({ &m_bit_buffer, bytes_to_write }));

        if (m_bit_count == bit_buffer_size) {
            m_bit_buffer = 0;
            m_bit_count = 0;
        } else {
            auto bits_written = bytes_to_write * bits_per_byte;

            m_bit_buffer >>= bits_written;
            m_bit_count -= bits_written;
        }

        return {};
    }

    virtual bool is_eof() const override
    {
        return true;
    }

    virtual bool is_open() const override
    {
        return m_stream->is_open();
    }

    virtual void close() override
    {
    }

    size_t bit_offset() const
    {
        return m_bit_count;
    }

    ErrorOr<void> align_to_byte_boundary()
    {
        if (auto offset = m_bit_count % bits_per_byte; offset != 0)
            TRY(write_bits<u8>(0u, bits_per_byte - offset));

        return {};
    }
};

template<typename T>
concept InputBitStream = OneOf<T, BigEndianInputBitStream, LittleEndianInputBitStream>;

}

#if USING_AK_GLOBALLY
using AK::InputBitStream;
#endif
