/*
 *   This file is part of PKSM-Core
 *   Copyright (C) 2016-2022 Bernardo Giordano, Admiral Fish, piepie62
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

#ifndef PERSONAL_HPP
#define PERSONAL_HPP

#include "enums/Ability.hpp"
#include "enums/Type.hpp"
#include "utils/coretypes.h"

namespace pksm
{
    namespace PersonalLGPE
    {
        [[nodiscard]] u8 baseHP(u16 formSpecies);
        [[nodiscard]] u8 baseAtk(u16 formSpecies);
        [[nodiscard]] u8 baseDef(u16 formSpecies);
        [[nodiscard]] u8 baseSpe(u16 formSpecies);
        [[nodiscard]] u8 baseSpa(u16 formSpecies);
        [[nodiscard]] u8 baseSpd(u16 formSpecies);
        [[nodiscard]] Type type1(u16 formSpecies);
        [[nodiscard]] Type type2(u16 formSpecies);
        [[nodiscard]] u8 gender(u16 formSpecies);
        [[nodiscard]] u8 baseFriendship(u16 formSpecies);
        [[nodiscard]] u8 expType(u16 formSpecies);
        [[nodiscard]] Ability ability(u16 formSpecies, u8 n);
        [[nodiscard]] u16 formStatIndex(u16 formSpecies);
        [[nodiscard]] u8 formCount(u16 formSpecies);
    }

    namespace PersonalSMUSUM
    {
        [[nodiscard]] u8 baseHP(u16 formSpecies);
        [[nodiscard]] u8 baseAtk(u16 formSpecies);
        [[nodiscard]] u8 baseDef(u16 formSpecies);
        [[nodiscard]] u8 baseSpe(u16 formSpecies);
        [[nodiscard]] u8 baseSpa(u16 formSpecies);
        [[nodiscard]] u8 baseSpd(u16 formSpecies);
        [[nodiscard]] Type type1(u16 formSpecies);
        [[nodiscard]] Type type2(u16 formSpecies);
        [[nodiscard]] u8 gender(u16 formSpecies);
        [[nodiscard]] u8 baseFriendship(u16 formSpecies);
        [[nodiscard]] u8 expType(u16 formSpecies);
        [[nodiscard]] Ability ability(u16 formSpecies, u8 n);
        [[nodiscard]] u16 formStatIndex(u16 formSpecies);
        [[nodiscard]] u8 formCount(u16 formSpecies);
    }

    namespace PersonalXYORAS
    {
        [[nodiscard]] u8 baseHP(u16 formSpecies);
        [[nodiscard]] u8 baseAtk(u16 formSpecies);
        [[nodiscard]] u8 baseDef(u16 formSpecies);
        [[nodiscard]] u8 baseSpe(u16 formSpecies);
        [[nodiscard]] u8 baseSpa(u16 formSpecies);
        [[nodiscard]] u8 baseSpd(u16 formSpecies);
        [[nodiscard]] Type type1(u16 formSpecies);
        [[nodiscard]] Type type2(u16 formSpecies);
        [[nodiscard]] u8 gender(u16 formSpecies);
        [[nodiscard]] u8 baseFriendship(u16 formSpecies);
        [[nodiscard]] u8 expType(u16 formSpecies);
        [[nodiscard]] Ability ability(u16 formSpecies, u8 n);
        [[nodiscard]] u16 formStatIndex(u16 formSpecies);
        [[nodiscard]] u8 formCount(u16 formSpecies);
    }

    namespace PersonalBWB2W2
    {
        [[nodiscard]] u8 baseHP(u16 formSpecies);
        [[nodiscard]] u8 baseAtk(u16 formSpecies);
        [[nodiscard]] u8 baseDef(u16 formSpecies);
        [[nodiscard]] u8 baseSpe(u16 formSpecies);
        [[nodiscard]] u8 baseSpa(u16 formSpecies);
        [[nodiscard]] u8 baseSpd(u16 formSpecies);
        [[nodiscard]] Type type1(u16 formSpecies);
        [[nodiscard]] Type type2(u16 formSpecies);
        [[nodiscard]] u8 gender(u16 formSpecies);
        [[nodiscard]] u8 baseFriendship(u16 formSpecies);
        [[nodiscard]] u8 expType(u16 formSpecies);
        [[nodiscard]] Ability ability(u16 formSpecies, u8 n);
        [[nodiscard]] u16 formStatIndex(u16 formSpecies);
        [[nodiscard]] u8 formCount(u16 formSpecies);
    }

    namespace PersonalDPPtHGSS
    {
        [[nodiscard]] u8 baseHP(u16 formSpecies);
        [[nodiscard]] u8 baseAtk(u16 formSpecies);
        [[nodiscard]] u8 baseDef(u16 formSpecies);
        [[nodiscard]] u8 baseSpe(u16 formSpecies);
        [[nodiscard]] u8 baseSpa(u16 formSpecies);
        [[nodiscard]] u8 baseSpd(u16 formSpecies);
        [[nodiscard]] Type type1(u16 formSpecies);
        [[nodiscard]] Type type2(u16 formSpecies);
        [[nodiscard]] u8 gender(u16 formSpecies);
        [[nodiscard]] u8 baseFriendship(u16 formSpecies);
        [[nodiscard]] u8 expType(u16 formSpecies);
        [[nodiscard]] Ability ability(u16 formSpecies, u8 n);
        [[nodiscard]] u16 formStatIndex(u16 formSpecies);
        [[nodiscard]] u8 formCount(u16 formSpecies);
    }

    namespace PersonalSWSH
    {
        [[nodiscard]] u8 baseHP(u16 formSpecies);
        [[nodiscard]] u8 baseAtk(u16 formSpecies);
        [[nodiscard]] u8 baseDef(u16 formSpecies);
        [[nodiscard]] u8 baseSpe(u16 formSpecies);
        [[nodiscard]] u8 baseSpa(u16 formSpecies);
        [[nodiscard]] u8 baseSpd(u16 formSpecies);
        [[nodiscard]] Type type1(u16 formSpecies);
        [[nodiscard]] Type type2(u16 formSpecies);
        [[nodiscard]] u8 gender(u16 formSpecies);
        [[nodiscard]] u8 baseFriendship(u16 formSpecies);
        [[nodiscard]] u8 expType(u16 formSpecies);
        [[nodiscard]] Ability ability(u16 formSpecies, u8 n);
        [[nodiscard]] u16 formStatIndex(u16 formSpecies);
        [[nodiscard]] u8 formCount(u16 formSpecies);
        [[nodiscard]] u16 pokedexIndex(u16 formSpecies);
        [[nodiscard]] u16 armordexIndex(u16 species);
        [[nodiscard]] u16 crowndexIndex(u16 species);
        [[nodiscard]] bool canLearnTR(u16 formSpecies, u8 trID);
    }

    namespace PersonalRSFRLGE
    {
        [[nodiscard]] u8 baseHP(u16 formSpecies);
        [[nodiscard]] u8 baseAtk(u16 formSpecies);
        [[nodiscard]] u8 baseDef(u16 formSpecies);
        [[nodiscard]] u8 baseSpe(u16 formSpecies);
        [[nodiscard]] u8 baseSpa(u16 formSpecies);
        [[nodiscard]] u8 baseSpd(u16 formSpecies);
        [[nodiscard]] Type type1(u16 formSpecies);
        [[nodiscard]] Type type2(u16 formSpecies);
        [[nodiscard]] u8 gender(u16 formSpecies);
        [[nodiscard]] u8 baseFriendship(u16 formSpecies);
        [[nodiscard]] u8 expType(u16 formSpecies);
        [[nodiscard]] Ability ability(u16 formSpecies, u8 n);
        [[nodiscard]] u8 formCount(u16 formSpecies);
    }

    namespace PersonalGSC
    {
        [[nodiscard]] u8 baseHP(u8 species);
        [[nodiscard]] u8 baseAtk(u8 species);
        [[nodiscard]] u8 baseDef(u8 species);
        [[nodiscard]] u8 baseSpe(u8 species);
        [[nodiscard]] u8 baseSpa(u8 species);
        [[nodiscard]] u8 baseSpd(u8 species);
        [[nodiscard]] Type type1(u8 species);
        [[nodiscard]] Type type2(u8 species);
        [[nodiscard]] u8 gender(u8 species);
        [[nodiscard]] u8 expType(u8 species);
        [[nodiscard]] u8 formCount(u16 formSpecies);
    }

    namespace PersonalRGBY
    {
        [[nodiscard]] u8 baseHP(u8 species);
        [[nodiscard]] u8 baseAtk(u8 species);
        [[nodiscard]] u8 baseDef(u8 species);
        [[nodiscard]] u8 baseSpe(u8 species);
        [[nodiscard]] u8 baseSpad(u8 species);
        [[nodiscard]] Type type1(u8 species);
        [[nodiscard]] Type type2(u8 species);
        [[nodiscard]] u8 catchRate(u8 species);
        [[nodiscard]] u8 expType(u8 species);
    }

    namespace PersonalSV
    {
        [[nodiscard]] u8 baseHP(u16 formSpecies);
        [[nodiscard]] u8 baseAtk(u16 formSpecies);
        [[nodiscard]] u8 baseDef(u16 formSpecies);
        [[nodiscard]] u8 baseSpe(u16 formSpecies);
        [[nodiscard]] u8 baseSpa(u16 formSpecies);
        [[nodiscard]] u8 baseSpd(u16 formSpecies);
        [[nodiscard]] Type type1(u16 formSpecies);
        [[nodiscard]] Type type2(u16 formSpecies);
        [[nodiscard]] u8 gender(u16 formSpecies);
        [[nodiscard]] u8 baseFriendship(u16 formSpecies);
        [[nodiscard]] u8 expType(u16 formSpecies);
        [[nodiscard]] Ability ability(u16 formSpecies, u8 n);
        [[nodiscard]] u16 formStatIndex(u16 formSpecies);
        [[nodiscard]] u8 formCount(u16 formSpecies);
        [[nodiscard]] u16 pokedexIndex(u16 formSpecies);
        [[nodiscard]] bool canLearnTR(u16 formSpecies, u8 trID);
    }
}

#endif
