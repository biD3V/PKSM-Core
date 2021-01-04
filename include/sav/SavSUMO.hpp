/*
 *   This file is part of PKSM-Core
 *   Copyright (C) 2016-2020 Bernardo Giordano, Admiral Fish, piepie62
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

#ifndef SAVSUMO_HPP
#define SAVSUMO_HPP

#include "sav/Sav7.hpp"

namespace pksm
{
    class SavSUMO : public Sav7
    {
    protected:
        static constexpr u32 chkofs[37] = {0x00000, 0x00E00, 0x01000, 0x01200, 0x01400, 0x01C00,
            0x02A00, 0x03A00, 0x03E00, 0x04000, 0x04200, 0x04400, 0x04600, 0x04800, 0x04E00,
            0x3B400, 0x40C00, 0x40E00, 0x42000, 0x43C00, 0x4A200, 0x50800, 0x54200, 0x54400,
            0x54600, 0x64C00, 0x65000, 0x65C00, 0x69C00, 0x6A000, 0x6A800, 0x6AA00, 0x6B200,
            0x6B400, 0x6B600, 0x6B800, 0x6BA00};

        static constexpr u32 chklen[37] = {0xDE0, 0x07C, 0x014, 0x0C0, 0x61C, 0xE00, 0xF78, 0x228,
            0x104, 0x200, 0x020, 0x004, 0x058, 0x5E6, 0x36600, 0x572C, 0x008, 0x1080, 0x1A08,
            0x6408, 0x6408, 0x3998, 0x100, 0x100, 0x10528, 0x204, 0xB60, 0x3F50, 0x358, 0x728,
            0x200, 0x718, 0x1FC, 0x200, 0x120, 0x1C8, 0x200};

        // u16 species, u16 formcount
        static constexpr u16 formtable[230] = {0x0003, 0x0002, 0x0006, 0x0003, 0x0009, 0x0002,
            0x000F, 0x0002, 0x0012, 0x0002, 0x0013, 0x0002, 0x0014, 0x0003, 0x0019, 0x0007, 0x001A,
            0x0002, 0x001B, 0x0002, 0x001C, 0x0002, 0x0025, 0x0002, 0x0026, 0x0002, 0x0032, 0x0002,
            0x0033, 0x0002, 0x0034, 0x0002, 0x0035, 0x0002, 0x0041, 0x0002, 0x004A, 0x0002, 0x004B,
            0x0002, 0x004C, 0x0002, 0x0050, 0x0002, 0x0058, 0x0002, 0x0059, 0x0002, 0x005E, 0x0002,
            0x0067, 0x0002, 0x0069, 0x0002, 0x0073, 0x0002, 0x007F, 0x0002, 0x0082, 0x0002, 0x008E,
            0x0002, 0x0096, 0x0003, 0x00B5, 0x0002, 0x00C9, 0x001C, 0x00D0, 0x0002, 0x00D4, 0x0002,
            0x00D6, 0x0002, 0x00E5, 0x0002, 0x00F8, 0x0002, 0x00FE, 0x0002, 0x0101, 0x0002, 0x0104,
            0x0002, 0x011A, 0x0002, 0x012E, 0x0002, 0x012F, 0x0002, 0x0132, 0x0002, 0x0134, 0x0002,
            0x0136, 0x0002, 0x013F, 0x0002, 0x0143, 0x0002, 0x014E, 0x0002, 0x015F, 0x0004, 0x0162,
            0x0002, 0x0167, 0x0002, 0x016A, 0x0002, 0x0175, 0x0002, 0x0178, 0x0002, 0x017C, 0x0002,
            0x017D, 0x0002, 0x017E, 0x0002, 0x017F, 0x0002, 0x0180, 0x0002, 0x0182, 0x0004, 0x019C,
            0x0003, 0x019D, 0x0003, 0x01A5, 0x0002, 0x01A6, 0x0002, 0x01A7, 0x0002, 0x01AC, 0x0002,
            0x01BD, 0x0002, 0x01C0, 0x0002, 0x01CC, 0x0002, 0x01DB, 0x0002, 0x01DF, 0x0006, 0x01E7,
            0x0002, 0x01EC, 0x0002, 0x01ED, 0x0012, 0x0213, 0x0002, 0x0226, 0x0002, 0x022B, 0x0002,
            0x0249, 0x0004, 0x024A, 0x0004, 0x0281, 0x0002, 0x0282, 0x0002, 0x0285, 0x0002, 0x0286,
            0x0003, 0x0287, 0x0002, 0x0288, 0x0002, 0x0289, 0x0005, 0x0292, 0x0003, 0x029A, 0x0014,
            0x029D, 0x0005, 0x029E, 0x0006, 0x029F, 0x0005, 0x02A4, 0x000A, 0x02A6, 0x0002, 0x02A9,
            0x0002, 0x02C6, 0x0004, 0x02C7, 0x0004, 0x02CC, 0x0002, 0x02CE, 0x0005, 0x02CF, 0x0002,
            0x02D0, 0x0002, 0x02DF, 0x0002, 0x02E2, 0x0002, 0x02E5, 0x0004, 0x02E9, 0x0002, 0x02EA,
            0x0002, 0x02F2, 0x0002, 0x02F6, 0x0002, 0x0305, 0x0012, 0x0306, 0x000E, 0x030A, 0x0004,
            0x0310, 0x0002, 0x0321, 0x0002};

        int dexFormIndex(int species, int formct, int start) const override;
        int dexFormCount(int species) const override;

    public:
        explicit SavSUMO(std::shared_ptr<u8[]> dt);

        void resign(void) override;

        [[nodiscard]] std::map<Pouch, std::vector<int>> validItems(void) const override;
    };
}

#endif
