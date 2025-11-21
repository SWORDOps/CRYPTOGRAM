/*
This file is part of CRYPTOGRAM,
the most advanced secure messaging application for secure messaging.

For license and copyright information please follow this link:
https://github.com/SWORDOps/CRYPTOGRAM/blob/main/LICENSE
*/
#pragma once

#include "base/bytes.h"
#include <QString>

namespace Data {

bytes::vector deriveSignalHKDF(
        const bytes::const_span &inputKeyMaterial,
        const QString &info,
        size_t outputLength);

} // namespace Data
