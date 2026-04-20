/*
 * CRYPTOGRAM Settings Activity
 * Military-Grade Encryption Settings for Telegram Android
 *
 * This file is part of CRYPTOGRAM Android
 * Licensed under GNU GPL v. 2 or later.
 */

package org.telegram.ui;

import android.content.Context;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;

import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import org.telegram.messenger.AndroidUtilities;
import org.telegram.messenger.LocaleController;
import org.telegram.messenger.MessagesController;
import org.telegram.messenger.R;
import org.telegram.messenger.SharedConfig;
import org.telegram.messenger.cryptogram.CryptogramNative;
import org.telegram.messenger.cryptogram.DoubleRatchet;
import org.telegram.messenger.cryptogram.MLSProtocol;
import org.telegram.ui.ActionBar.ActionBar;
import org.telegram.ui.ActionBar.BaseFragment;
import org.telegram.ui.ActionBar.Theme;
import org.telegram.ui.ActionBar.ThemeDescription;
import org.telegram.ui.Cells.HeaderCell;
import org.telegram.ui.Cells.ShadowSectionCell;
import org.telegram.ui.Cells.TextCheckCell;
import org.telegram.ui.Cells.TextInfoPrivacyCell;
import org.telegram.ui.Cells.TextSettingsCell;
import org.telegram.ui.Components.LayoutHelper;
import org.telegram.ui.Components.RecyclerListView;

import java.util.ArrayList;
import java.util.Map;

public class CryptogramSettingsActivity extends BaseFragment {

    private RecyclerListView listView;
    private ListAdapter listAdapter;
    private LinearLayoutManager layoutManager;

    // Row indices
    private int rowCount;

    private int cryptogramHeaderRow;
    private int cryptogramStatusRow;
    private int cryptogramShadowRow;

    private int encryptionSectionRow;
    private int doubleRatchetRow;
    private int mlsProtocolRow;
    private int encryptionInfoRow;

    private int privacySectionRow;
    private int hideOnlineStatusRow;
    private int hideTypingIndicatorRow;
    private int hideReadReceiptsRow;
    private int privacyInfoRow;

    private int uiSectionRow;
    private int curatedStickersRow;
    private int uiInfoRow;

    private int advancedSectionRow;
    private int libraryVersionRow;
    private int featureStatusRow;
    private int advancedInfoRow;

    @Override
    public boolean onFragmentCreate() {
        super.onFragmentCreate();
        updateRows();
        return true;
    }

    @Override
    public View createView(Context context) {
        actionBar.setBackButtonImage(R.drawable.ic_ab_back);
        actionBar.setAllowOverlayTitle(true);
        actionBar.setTitle("CRYPTOGRAM");
        actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() {
            @Override
            public void onItemClick(int id) {
                if (id == -1) {
                    finishFragment();
                }
            }
        });

        listAdapter = new ListAdapter(context);

        fragmentView = new FrameLayout(context);
        fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        FrameLayout frameLayout = (FrameLayout) fragmentView;

        listView = new RecyclerListView(context);
        listView.setVerticalScrollBarEnabled(false);
        listView.setLayoutManager(layoutManager = new LinearLayoutManager(context, LinearLayoutManager.VERTICAL, false));
        frameLayout.addView(listView, LayoutHelper.createFrame(LayoutHelper.MATCH_PARENT, LayoutHelper.MATCH_PARENT));
        listView.setAdapter(listAdapter);
        listView.setOnItemClickListener((view, position, x, y) -> {
            if (position == doubleRatchetRow) {
                SharedConfig.toggleCryptogramDoubleRatchet();
                if (view instanceof TextCheckCell) {
                    ((TextCheckCell) view).setChecked(SharedConfig.cryptogramDoubleRatchetEnabled);
                }
            } else if (position == mlsProtocolRow) {
                SharedConfig.toggleCryptogramMLS();
                if (view instanceof TextCheckCell) {
                    ((TextCheckCell) view).setChecked(SharedConfig.cryptogramMLSEnabled);
                }
            } else if (position == hideOnlineStatusRow) {
                SharedConfig.toggleCryptogramHideOnlineStatus();
                if (view instanceof TextCheckCell) {
                    ((TextCheckCell) view).setChecked(SharedConfig.cryptogramHideOnlineStatus);
                }
            } else if (position == hideTypingIndicatorRow) {
                SharedConfig.toggleCryptogramHideTypingIndicator();
                if (view instanceof TextCheckCell) {
                    ((TextCheckCell) view).setChecked(SharedConfig.cryptogramHideTypingIndicator);
                }
            } else if (position == hideReadReceiptsRow) {
                SharedConfig.toggleCryptogramHideReadReceipts();
                if (view instanceof TextCheckCell) {
                    ((TextCheckCell) view).setChecked(SharedConfig.cryptogramHideReadReceipts);
                }
            } else if (position == curatedStickersRow) {
                SharedConfig.toggleCryptogramCuratedStickers();
                if (view instanceof TextCheckCell) {
                    ((TextCheckCell) view).setChecked(SharedConfig.cryptogramCuratedStickersEnabled);
                }
            } else if (position == featureStatusRow) {
                showFeatureStatusDialog();
            }
        });

        return fragmentView;
    }

    private void updateRows() {
        rowCount = 0;

        cryptogramHeaderRow = rowCount++;
        cryptogramStatusRow = rowCount++;
        cryptogramShadowRow = rowCount++;

        encryptionSectionRow = rowCount++;
        doubleRatchetRow = rowCount++;
        mlsProtocolRow = rowCount++;
        encryptionInfoRow = rowCount++;

        privacySectionRow = rowCount++;
        hideOnlineStatusRow = rowCount++;
        hideTypingIndicatorRow = rowCount++;
        hideReadReceiptsRow = rowCount++;
        privacyInfoRow = rowCount++;

        uiSectionRow = rowCount++;
        curatedStickersRow = rowCount++;
        uiInfoRow = rowCount++;

        advancedSectionRow = rowCount++;
        libraryVersionRow = rowCount++;
        featureStatusRow = rowCount++;
        advancedInfoRow = rowCount++;
    }

    private void showFeatureStatusDialog() {
        Map<String, Boolean> status = CryptogramNative.INSTANCE.getFeatureStatus();
        StringBuilder message = new StringBuilder();
        message.append("CRYPTOGRAM Feature Status:\n\n");

        for (Map.Entry<String, Boolean> entry : status.entrySet()) {
            String icon = entry.getValue() ? "✓" : "✗";
            message.append(icon).append(" ").append(entry.getKey()).append("\n");
        }

        AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
        builder.setTitle("Feature Status");
        builder.setMessage(message.toString());
        builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
        showDialog(builder.create());
    }

    private class ListAdapter extends RecyclerListView.SelectionAdapter {

        private Context mContext;

        public ListAdapter(Context context) {
            mContext = context;
        }

        @Override
        public int getItemCount() {
            return rowCount;
        }

        @Override
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            switch (holder.getItemViewType()) {
                case 0: {
                    // Shadow
                    break;
                }
                case 1: {
                    // TextSettingsCell
                    TextSettingsCell textCell = (TextSettingsCell) holder.itemView;
                    if (position == cryptogramStatusRow) {
                        Map<String, Boolean> status = CryptogramNative.INSTANCE.getFeatureStatus();
                        boolean nativeReady = Boolean.TRUE.equals(status.get("Native Library"));
                        boolean ratchetReady = Boolean.TRUE.equals(status.get("Double Ratchet"));
                        boolean mlsReady = Boolean.TRUE.equals(status.get("MLS Protocol"));
                        String value;
                        if (nativeReady && ratchetReady && mlsReady) {
                            value = "🔐 Local self-checks passed";
                        } else if (nativeReady) {
                            value = "⚠️ Native loaded, partial checks";
                        } else {
                            value = "⚠️ Native library unavailable";
                        }
                        textCell.setTextAndValue("Status", value, false);
                    } else if (position == libraryVersionRow) {
                        String version = CryptogramNative.INSTANCE.getVersion();
                        textCell.setTextAndValue("Library Version", version, false);
                    } else if (position == featureStatusRow) {
                        textCell.setText("Feature Status", true);
                    }
                    break;
                }
                case 2: {
                    // HeaderCell
                    HeaderCell headerCell = (HeaderCell) holder.itemView;
                    if (position == cryptogramHeaderRow) {
                        headerCell.setText("🔐 CRYPTOGRAM");
                    } else if (position == encryptionSectionRow) {
                        headerCell.setText("Encryption Protocols");
                    } else if (position == privacySectionRow) {
                        headerCell.setText("Privacy Settings");
                    } else if (position == uiSectionRow) {
                        headerCell.setText("UI/UX Preferences");
                    } else if (position == advancedSectionRow) {
                        headerCell.setText("Advanced");
                    }
                    break;
                }
                case 3: {
                    // TextCheckCell
                    TextCheckCell textCheckCell = (TextCheckCell) holder.itemView;
                    if (position == doubleRatchetRow) {
                        textCheckCell.setTextAndCheck("Double Ratchet (Signal Protocol)",
                            SharedConfig.cryptogramDoubleRatchetEnabled, true);
                    } else if (position == mlsProtocolRow) {
                        textCheckCell.setTextAndCheck("MLS for Groups (RFC 9420)",
                            SharedConfig.cryptogramMLSEnabled, true);
                    } else if (position == hideOnlineStatusRow) {
                        textCheckCell.setTextAndCheck("Hide Online Status",
                            SharedConfig.cryptogramHideOnlineStatus, true);
                    } else if (position == hideTypingIndicatorRow) {
                        textCheckCell.setTextAndCheck("Hide Typing Indicator",
                            SharedConfig.cryptogramHideTypingIndicator, true);
                    } else if (position == hideReadReceiptsRow) {
                        textCheckCell.setTextAndCheck("Hide Read Receipts",
                            SharedConfig.cryptogramHideReadReceipts, false);
                    } else if (position == curatedStickersRow) {
                        textCheckCell.setTextAndCheck("Curated Stickers",
                            SharedConfig.cryptogramCuratedStickersEnabled, true);
                    }
                    break;
                }
                case 4: {
                    // TextInfoPrivacyCell
                    TextInfoPrivacyCell cell = (TextInfoPrivacyCell) holder.itemView;
                    if (position == cryptogramShadowRow) {
                        cell.setText("CRYPTOGRAM adds native cryptography and privacy controls to Telegram. Feature availability below reflects local native self-checks and runtime wiring, not a full external security audit.");
                    } else if (position == encryptionInfoRow) {
                        cell.setText("• Double Ratchet: End-to-end encryption for 1-on-1 chats using Signal Protocol (X25519, Ed25519, AES-256-GCM)\n\n" +
                                    "• MLS Protocol: Scalable group encryption with TreeKEM (O(log n) operations, supports 10,000+ members)\n\n" +
                                    "Both protocols are exposed through the CRYPTOGRAM native layer. Use Feature Status to verify the local runtime path before relying on them.");
                    } else if (position == privacyInfoRow) {
                        cell.setText("• Hide Online Status: Prevents sending your online/offline status to other users\n\n" +
                                    "• Hide Typing Indicator: Stops sending typing notifications when you compose messages\n\n" +
                                    "• Hide Read Receipts: Prevents sending read confirmations (double ticks) when you view messages\n\n" +
                                    "These settings enhance your privacy by controlling what activity information is shared.");
                    } else if (position == uiInfoRow) {
                        cell.setText("Curated Stickers: Show a favorites section at the top of your sticker picker with your most-used sticker sets for quick access. All stickers remain searchable.\n\n" +
                                    "Long-press any sticker to add or remove its set from your curated favorites.");
                    } else if (position == advancedInfoRow) {
                        cell.setText("CRYPTOGRAM performs cryptographic operations locally through the native library. Feature Status runs local self-checks for the current build; device-level interoperability and broader security validation still depend on your target environment.\n\n" +
                                    "For technical details, see the CRYPTOGRAM documentation.");
                    }
                    break;
                }
            }
        }

        @Override
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            int type = holder.getItemViewType();
            return type == 1 || type == 3;
        }

        @Override
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view;
            switch (viewType) {
                case 0:
                    view = new ShadowSectionCell(mContext);
                    break;
                case 1:
                    view = new TextSettingsCell(mContext);
                    view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                    break;
                case 2:
                    view = new HeaderCell(mContext);
                    view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                    break;
                case 3:
                    view = new TextCheckCell(mContext);
                    view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                    break;
                case 4:
                default:
                    view = new TextInfoPrivacyCell(mContext);
                    break;
            }
            view.setLayoutParams(new RecyclerView.LayoutParams(RecyclerView.LayoutParams.MATCH_PARENT, RecyclerView.LayoutParams.WRAP_CONTENT));
            return new RecyclerListView.Holder(view);
        }

        @Override
        public int getItemViewType(int position) {
            if (position == cryptogramShadowRow) {
                return 0; // Shadow
            } else if (position == cryptogramStatusRow || position == libraryVersionRow || position == featureStatusRow) {
                return 1; // TextSettingsCell
            } else if (position == cryptogramHeaderRow || position == encryptionSectionRow || position == privacySectionRow || position == uiSectionRow || position == advancedSectionRow) {
                return 2; // HeaderCell
            } else if (position == doubleRatchetRow || position == mlsProtocolRow || position == hideOnlineStatusRow || position == hideTypingIndicatorRow || position == hideReadReceiptsRow || position == curatedStickersRow) {
                return 3; // TextCheckCell
            } else if (position == encryptionInfoRow || position == privacyInfoRow || position == uiInfoRow || position == advancedInfoRow) {
                return 4; // TextInfoPrivacyCell
            }
            return 0;
        }
    }

    @Override
    public ArrayList<ThemeDescription> getThemeDescriptions() {
        ArrayList<ThemeDescription> themeDescriptions = new ArrayList<>();

        themeDescriptions.add(new ThemeDescription(listView, ThemeDescription.FLAG_CELLBACKGROUNDCOLOR, new Class[]{TextSettingsCell.class, TextCheckCell.class, HeaderCell.class}, null, null, null, Theme.key_windowBackgroundWhite));
        themeDescriptions.add(new ThemeDescription(fragmentView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundGray));

        themeDescriptions.add(new ThemeDescription(actionBar, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_actionBarDefault));
        themeDescriptions.add(new ThemeDescription(listView, ThemeDescription.FLAG_LISTGLOWCOLOR, null, null, null, null, Theme.key_actionBarDefault));
        themeDescriptions.add(new ThemeDescription(actionBar, ThemeDescription.FLAG_AB_ITEMSCOLOR, null, null, null, null, Theme.key_actionBarDefaultIcon));
        themeDescriptions.add(new ThemeDescription(actionBar, ThemeDescription.FLAG_AB_TITLECOLOR, null, null, null, null, Theme.key_actionBarDefaultTitle));
        themeDescriptions.add(new ThemeDescription(actionBar, ThemeDescription.FLAG_AB_SELECTORCOLOR, null, null, null, null, Theme.key_actionBarDefaultSelector));

        themeDescriptions.add(new ThemeDescription(listView, ThemeDescription.FLAG_SELECTOR, null, null, null, null, Theme.key_listSelector));

        themeDescriptions.add(new ThemeDescription(listView, 0, new Class[]{View.class}, Theme.dividerPaint, null, null, Theme.key_divider));

        themeDescriptions.add(new ThemeDescription(listView, 0, new Class[]{HeaderCell.class}, new String[]{"textView"}, null, null, null, Theme.key_windowBackgroundWhiteBlueHeader));

        themeDescriptions.add(new ThemeDescription(listView, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{ShadowSectionCell.class}, null, null, null, Theme.key_windowBackgroundGrayShadow));

        themeDescriptions.add(new ThemeDescription(listView, 0, new Class[]{TextSettingsCell.class}, new String[]{"textView"}, null, null, null, Theme.key_windowBackgroundWhiteBlackText));
        themeDescriptions.add(new ThemeDescription(listView, 0, new Class[]{TextSettingsCell.class}, new String[]{"valueTextView"}, null, null, null, Theme.key_windowBackgroundWhiteValueText));

        themeDescriptions.add(new ThemeDescription(listView, 0, new Class[]{TextCheckCell.class}, new String[]{"textView"}, null, null, null, Theme.key_windowBackgroundWhiteBlackText));
        themeDescriptions.add(new ThemeDescription(listView, 0, new Class[]{TextCheckCell.class}, new String[]{"checkBox"}, null, null, null, Theme.key_switchTrack));
        themeDescriptions.add(new ThemeDescription(listView, 0, new Class[]{TextCheckCell.class}, new String[]{"checkBox"}, null, null, null, Theme.key_switchTrackChecked));

        themeDescriptions.add(new ThemeDescription(listView, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{TextInfoPrivacyCell.class}, null, null, null, Theme.key_windowBackgroundGrayShadow));
        themeDescriptions.add(new ThemeDescription(listView, 0, new Class[]{TextInfoPrivacyCell.class}, new String[]{"textView"}, null, null, null, Theme.key_windowBackgroundWhiteGrayText4));

        return themeDescriptions;
    }
}
