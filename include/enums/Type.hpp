/*
 *   This file is part of PKSM-Core
 *   Copyright (C) 2016-2020 Bernardo Giordano, Admiral Fish, piepie62, Pk11
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *   Additional Terms 7.b and 7.c of GPLv3 apply to this file:
 *       * Requiring preservation of specified reasonable legal notices or
 *         author attributions in that material or in the Appropriate Legal
 *         Notices displayed by works containing it.
 *       * Prohibiting misrepresentation of the origin of that material,
 *         or requiring that modified versions of such material be marked in
 *         reasonable ways as different from the original version.
 */

#ifndef TYPE_HPP
#define TYPE_HPP

#include "enums/Language.hpp"
#include <limits>
#include <string>
#include <type_traits>

class Type_impl
{
    friend class Type;

private:
    enum class TypeEnum : u8
    {
        Normal,
        Fighting,
        Flying,
        Poison,
        Ground,
        Rock,
        Bug,
        Ghost,
        Steel,
        Fire,
        Water,
        Grass,
        Electric,
        Psychic,
        Ice,
        Dragon,
        Dark,
        Fairy,

        INVALID = std::numeric_limits<std::underlying_type_t<TypeEnum>>::max()
    } v;

    constexpr explicit Type_impl(TypeEnum v) : v(v) {}
    constexpr Type_impl(const Type_impl&) = default;
    constexpr Type_impl(Type_impl&&)      = default;
    constexpr Type_impl& operator=(const Type_impl&) = default;
    constexpr Type_impl& operator=(Type_impl&&) = default;

public:
    template <typename T>
    constexpr explicit operator T() const noexcept
    {
        static_assert(std::is_integral_v<T>);
        return T(v);
    }
    constexpr operator TypeEnum() const noexcept { return v; }

    constexpr bool operator<(const Type_impl& other) const noexcept { return v < other.v; }
    constexpr bool operator<=(const Type_impl& other) const noexcept { return v <= other.v; }

    constexpr bool operator>(const Type_impl& other) const noexcept { return v > other.v; }
    constexpr bool operator>=(const Type_impl& other) const noexcept { return v >= other.v; }

    constexpr bool operator==(const Type_impl& other) const noexcept { return v == other.v; }
    constexpr bool operator!=(const Type_impl& other) const noexcept { return v != other.v; }

    const std::string& localize(Language lang) const;
};

class Type
{
private:
    Type_impl impl;

public:
    using EnumType = Type_impl::TypeEnum;
    constexpr Type() noexcept : impl(EnumType{0}) {}
    constexpr Type(const Type_impl& impl) noexcept : impl(impl) {}
    constexpr explicit Type(std::underlying_type_t<EnumType> v) noexcept : impl(EnumType{v}) {}
    template <typename T>
    constexpr explicit operator T() const noexcept
    {
        static_assert(std::is_integral_v<T>);
        return T(impl);
    }
    constexpr operator EnumType() const noexcept { return (EnumType)impl; }

    constexpr bool operator<(const Type& other) const noexcept { return impl < other.impl; }
    constexpr bool operator<=(const Type& other) const noexcept { return impl <= other.impl; }

    constexpr bool operator>(const Type& other) const noexcept { return impl > other.impl; }
    constexpr bool operator>=(const Type& other) const noexcept { return impl >= other.impl; }

    constexpr bool operator==(const Type& other) const noexcept { return impl == other.impl; }
    constexpr bool operator!=(const Type& other) const noexcept { return impl != other.impl; }

    constexpr bool operator<(const Type_impl& other) const noexcept { return impl < other; }
    constexpr bool operator<=(const Type_impl& other) const noexcept { return impl <= other; }

    constexpr bool operator>(const Type_impl& other) const noexcept { return impl > other; }
    constexpr bool operator>=(const Type_impl& other) const noexcept { return impl >= other; }

    constexpr bool operator==(const Type_impl& other) const noexcept { return impl == other; }
    constexpr bool operator!=(const Type_impl& other) const noexcept { return impl != other; }

    const std::string& localize(Language lang) const { return impl.localize(lang); }

    static constexpr Type_impl Normal{EnumType::Normal};
    static constexpr Type_impl Fighting{EnumType::Fighting};
    static constexpr Type_impl Flying{EnumType::Flying};
    static constexpr Type_impl Poison{EnumType::Poison};
    static constexpr Type_impl Ground{EnumType::Ground};
    static constexpr Type_impl Rock{EnumType::Rock};
    static constexpr Type_impl Bug{EnumType::Bug};
    static constexpr Type_impl Ghost{EnumType::Ghost};
    static constexpr Type_impl Steel{EnumType::Steel};
    static constexpr Type_impl Fire{EnumType::Fire};
    static constexpr Type_impl Water{EnumType::Water};
    static constexpr Type_impl Grass{EnumType::Grass};
    static constexpr Type_impl Electric{EnumType::Electric};
    static constexpr Type_impl Psychic{EnumType::Psychic};
    static constexpr Type_impl Ice{EnumType::Ice};
    static constexpr Type_impl Dragon{EnumType::Dragon};
    static constexpr Type_impl Dark{EnumType::Dark};
    static constexpr Type_impl Fairy{EnumType::Fairy};

    static constexpr Type_impl INVALID{EnumType::INVALID};
};

#endif