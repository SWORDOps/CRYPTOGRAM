/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

struct DrawToReplyRequest;
namespace Data {
class Session;
} // namespace Data

namespace Window {
class SessionController;
} // namespace Window

namespace HistoryView {

[[nodiscard]] QImage ResolveDrawToReplyImage(
	not_null<Data::Session*> data,
	const DrawToReplyRequest &request);

void OpenDrawToReplyEditor(
	not_null<Window::SessionController*> controller,
	QImage image,
	Fn<void(QImage &&)> done);

} // namespace HistoryView
