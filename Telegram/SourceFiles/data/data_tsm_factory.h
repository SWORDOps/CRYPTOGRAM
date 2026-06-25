/*
This file is part of CRYPTOGRAM,
the most advanced secure messaging application for secure messaging.

For license and copyright information please follow this link:
https://github.com/SWORDOps/CRYPTOGRAM/blob/main/LICENSE
*/
#pragma once

#include "data/data_tsm_interface.h"

#include <memory>

namespace Data {

class TSMFactory {
public:
	static std::unique_ptr<TSMInterface> createForPlatform();
};

} // namespace Data
