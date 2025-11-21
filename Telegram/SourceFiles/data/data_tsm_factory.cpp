/*
This file is part of CRYPTOGRAM,
the most advanced secure messaging application for secure messaging.

For license and copyright information please follow this link:
https://github.com/SWORDOps/CRYPTOGRAM/blob/main/LICENSE
*/
#include "data/data_tsm_factory.h"
#include "data/data_tsm_interface.h"

namespace Data {

std::unique_ptr<TSMInterface> TSMFactory::createForPlatform() {
    auto tsm = createSoftwareTSM();
    if (!tsm) {
        return nullptr;
    }
    return (tsm->initialize() == TSMResult::Success) ? std::move(tsm) : nullptr;
}

} // namespace Data
