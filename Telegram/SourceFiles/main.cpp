/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "core/launcher.h"
#include <iostream>

int main(int argc, char *argv[]) {
	std::cout << "========================================================================\n";
	std::cout << "NOTE: If you plan to use YubiKey Auth to securely unlock your session,\n";
	std::cout << "you may need to run this client with 'sudo' if udev rules are missing.\n";
	std::cout << "========================================================================\n";

	const auto launcher = Core::Launcher::Create(argc, argv);
	return launcher ? launcher->exec() : 1;
}
