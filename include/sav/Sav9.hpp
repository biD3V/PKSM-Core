#ifndef SAV9_HPP
#define SAV9_HPP

#include "personal/personal.hpp"
#include "sav/Sav.hpp"
#include "utils/crypto.hpp"

namespace pksm
{
    class Sav9 : public Sav
    {
    protected:
        std::vector<std::shared_ptr<pksm::crypto::swsh::SCBlock>> blocks;

        int Items, BoxLayout, TrainerCard, PlayTime, Status, Money, LP;

        bool encrypted = false;

    public:
        Sav9(const std::shared_ptr<u8[]>& dt, size_t length);

        [[nodiscard]] std::shared_ptr<pksm::crypto::swsh::SCBlock> getBlock(u32 key) const;

        void finishEditing(void) override;
        void beginEditing(void) override;

        void trade(PKX& pk, const Date& date = Date::today()) const override;
        [[nodiscard]] std::unique_ptr<PKX> emptyPkm() const override;

        [[nodiscard]] int maxBoxes(void) const override { return 32; }

        [[nodiscard]] size_t maxWondercards(void) const override { return 1; } // Data not stored

        [[nodiscard]] int currentGiftAmount(void) const override { return 0; } // Data not stored

        [[nodiscard]] Generation generation(void) const override { return Generation::NINE; }
    };
}

#endif
