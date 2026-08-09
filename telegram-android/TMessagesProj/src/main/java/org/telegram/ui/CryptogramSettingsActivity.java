package org.telegram.ui;

import static org.telegram.messenger.LocaleController.getString;

import android.content.Context;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;

import androidx.annotation.Keep;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import org.telegram.messenger.AndroidUtilities;
import org.telegram.messenger.R;
import org.telegram.messenger.SharedConfig;
import org.telegram.messenger.cryptogram.CryptogramNative;
import org.telegram.ui.ActionBar.ActionBar;
import org.telegram.ui.ActionBar.BaseFragment;
import org.telegram.ui.ActionBar.Theme;
import org.telegram.ui.ActionBar.ThemeDescription;
import org.telegram.ui.Cells.HeaderCell;
import org.telegram.ui.Cells.ShadowSectionCell;
import org.telegram.ui.Cells.TextCell;
import org.telegram.ui.Cells.TextCheckCell;
import org.telegram.ui.Cells.TextInfoPrivacyCell;
import org.telegram.ui.Cells.TextSettingsCell;
import org.telegram.ui.Components.LayoutHelper;
import org.telegram.ui.Components.RecyclerListView;

import java.util.ArrayList;

public class CryptogramSettingsActivity extends BaseFragment {

    private ListAdapter listAdapter;
    private RecyclerListView listView;

    // Encryption section
    private int headerRow;
    private int doubleRatchetRow;
    private int doubleRatchetInfoRow;
    private int mlsRow;
    private int mlsInfoRow;
    private int shadowRow;

    // Privacy section
    private int privacyHeaderRow;
    private int hideOnlineRow;
    private int hideTypingRow;
    private int hideReadReceiptsRow;
    private int stylometryRow;
    private int antiForensicsRow;
    private int dpiEvasionRow;
    private int curatedStickersRow;
    private int privacyShadowRow;

    // Native section
    private int nativeSectionRow;
    private int nativeStatusRow;
    private int nativeVersionRow;
    private int doubleRatchetTestRow;
    private int mlsTestRow;
    private int selfTestButtonRow;
    private int selfTestInfoRow;

    private int rowCount;

    private Boolean doubleRatchetTestResult;
    private Boolean mlsTestResult;
    private boolean selfTestRunning;

    @Override
    public boolean onFragmentCreate() {
        super.onFragmentCreate();
        updateRows();
        return true;
    }

    private void updateRows() {
        rowCount = 0;

        // Encryption section
        headerRow = rowCount++;
        doubleRatchetRow = rowCount++;
        doubleRatchetInfoRow = rowCount++;
        mlsRow = rowCount++;
        mlsInfoRow = rowCount++;
        shadowRow = rowCount++;

        // Privacy section
        privacyHeaderRow = rowCount++;
        hideOnlineRow = rowCount++;
        hideTypingRow = rowCount++;
        hideReadReceiptsRow = rowCount++;
        stylometryRow = rowCount++;
        antiForensicsRow = rowCount++;
        dpiEvasionRow = rowCount++;
        curatedStickersRow = rowCount++;
        privacyShadowRow = rowCount++;

        // Native section
        nativeSectionRow = rowCount++;
        nativeStatusRow = rowCount++;
        nativeVersionRow = rowCount++;
        doubleRatchetTestRow = rowCount++;
        mlsTestRow = rowCount++;
        selfTestButtonRow = rowCount++;
        selfTestInfoRow = rowCount++;

        if (listAdapter != null) {
            listAdapter.notifyDataSetChanged();
        }
    }

    @Override
    public View createView(Context context) {
        actionBar.setBackButtonImage(R.drawable.ic_ab_back);
        actionBar.setAllowOverlayTitle(true);
        actionBar.setTitle(getString(R.string.CryptogramSettings));
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
        FrameLayout frameLayout = (FrameLayout) fragmentView;
        frameLayout.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));

        listView = new RecyclerListView(context);
        listView.setSections();
        actionBar.setAdaptiveBackground(listView);
        listView.setLayoutManager(new LinearLayoutManager(context, LinearLayoutManager.VERTICAL, false) {
            @Override
            public boolean supportsPredictiveItemAnimations() {
                return false;
            }
        });
        listView.setVerticalScrollBarEnabled(false);
        listView.setLayoutAnimation(null);
        listView.setItemAnimator(null);
        frameLayout.addView(listView, LayoutHelper.createFrame(LayoutHelper.MATCH_PARENT, LayoutHelper.MATCH_PARENT));
        listView.setAdapter(listAdapter);
        listView.setOnItemClickListener((view, position) -> {
            if (!view.isEnabled()) {
                return;
            }
            if (position == doubleRatchetRow) {
                SharedConfig.toggleCryptogramDoubleRatchet();
                if (view instanceof TextCheckCell) {
                    ((TextCheckCell) view).setChecked(SharedConfig.cryptogramDoubleRatchet);
                }
            } else if (position == mlsRow) {
                SharedConfig.toggleCryptogramMLS();
                if (view instanceof TextCheckCell) {
                    ((TextCheckCell) view).setChecked(SharedConfig.cryptogramMLS);
                }
            } else if (position == hideOnlineRow) {
                SharedConfig.toggleCryptogramHideOnlineStatus();
                if (view instanceof TextCheckCell) {
                    ((TextCheckCell) view).setChecked(SharedConfig.cryptogramHideOnlineStatus);
                }
            } else if (position == hideTypingRow) {
                SharedConfig.toggleCryptogramHideTypingIndicator();
                if (view instanceof TextCheckCell) {
                    ((TextCheckCell) view).setChecked(SharedConfig.cryptogramHideTypingIndicator);
                }
            } else if (position == hideReadReceiptsRow) {
                SharedConfig.toggleCryptogramHideReadReceipts();
                if (view instanceof TextCheckCell) {
                    ((TextCheckCell) view).setChecked(SharedConfig.cryptogramHideReadReceipts);
                }
            } else if (position == stylometryRow) {
                SharedConfig.toggleCryptogramStylometryShield();
                if (view instanceof TextCheckCell) {
                    ((TextCheckCell) view).setChecked(SharedConfig.cryptogramStylometryShield);
                }
            } else if (position == antiForensicsRow) {
                SharedConfig.toggleCryptogramAntiForensics();
                if (view instanceof TextCheckCell) {
                    ((TextCheckCell) view).setChecked(SharedConfig.cryptogramAntiForensics);
                }
            } else if (position == dpiEvasionRow) {
                SharedConfig.toggleCryptogramDpiEvasion();
                if (view instanceof TextCheckCell) {
                    ((TextCheckCell) view).setChecked(SharedConfig.cryptogramDpiEvasion);
                }
            } else if (position == curatedStickersRow) {
                SharedConfig.toggleCryptogramCuratedStickers();
                if (view instanceof TextCheckCell) {
                    ((TextCheckCell) view).setChecked(SharedConfig.cryptogramCuratedStickers);
                }
            } else if (position == selfTestButtonRow) {
                runSelfTest();
            }
        });

        return fragmentView;
    }

    private void runSelfTest() {
        if (selfTestRunning) {
            return;
        }
        selfTestRunning = true;
        doubleRatchetTestResult = null;
        mlsTestResult = null;
        if (listAdapter != null) {
            listAdapter.notifyItemChanged(selfTestButtonRow);
            listAdapter.notifyItemChanged(doubleRatchetTestRow);
            listAdapter.notifyItemChanged(mlsTestRow);
        }
        AndroidUtilities.runOnUIThread(() -> {
            doubleRatchetTestResult = CryptogramNative.INSTANCE.checkDoubleRatchet();
            mlsTestResult = CryptogramNative.INSTANCE.checkMLS();
            selfTestRunning = false;
            if (listAdapter != null) {
                listAdapter.notifyItemChanged(selfTestButtonRow);
                listAdapter.notifyItemChanged(doubleRatchetTestRow);
                listAdapter.notifyItemChanged(mlsTestRow);
            }
        }, 300);
    }

    @Override
    public void onResume() {
        super.onResume();
        if (listAdapter != null) {
            listAdapter.notifyDataSetChanged();
        }
    }

    private class ListAdapter extends RecyclerListView.SelectionAdapter {

        private Context mContext;

        public ListAdapter(Context context) {
            mContext = context;
        }

        @Override
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            int position = holder.getAdapterPosition();
            return position == doubleRatchetRow || position == mlsRow ||
                   position == hideOnlineRow || position == hideTypingRow ||
                   position == hideReadReceiptsRow || position == stylometryRow ||
                   position == antiForensicsRow || position == dpiEvasionRow ||
                   position == curatedStickersRow || position == selfTestButtonRow;
        }

        @Override
        public int getItemCount() {
            return rowCount;
        }

        @Override
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view;
            switch (viewType) {
                case 0:
                    view = new TextSettingsCell(mContext);
                    break;
                case 1:
                    view = new TextInfoPrivacyCell(mContext);
                    break;
                case 2:
                    view = new HeaderCell(mContext);
                    break;
                case 4:
                    view = new ShadowSectionCell(mContext);
                    break;
                case 5:
                    view = new TextCell(mContext);
                    break;
                case 3:
                default:
                    view = new TextCheckCell(mContext);
                    break;
            }
            return new RecyclerListView.Holder(view);
        }

        @Override
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            switch (holder.getItemViewType()) {
                case 0: {
                    TextSettingsCell textCell = (TextSettingsCell) holder.itemView;
                    if (position == nativeStatusRow) {
                        boolean loaded = CryptogramNative.INSTANCE.isLoaded();
                        textCell.setTextAndValue(getString(R.string.CryptogramNativeStatus), loaded ? getString(R.string.CryptogramSelfTestPass) : getString(R.string.CryptogramNotLoaded), true);
                    } else if (position == nativeVersionRow) {
                        textCell.setTextAndValue("Version", CryptogramNative.INSTANCE.getVersion(), true);
                    } else if (position == doubleRatchetTestRow) {
                        String value;
                        if (selfTestRunning) {
                            value = "...";
                        } else if (doubleRatchetTestResult == null) {
                            value = getString(R.string.CryptogramNotLoaded);
                        } else if (doubleRatchetTestResult) {
                            value = getString(R.string.CryptogramSelfTestPass);
                        } else {
                            value = getString(R.string.CryptogramSelfTestFail);
                        }
                        textCell.setTextAndValue("Double Ratchet", value, true);
                    } else if (position == mlsTestRow) {
                        String value;
                        if (selfTestRunning) {
                            value = "...";
                        } else if (mlsTestResult == null) {
                            value = getString(R.string.CryptogramNotLoaded);
                        } else if (mlsTestResult) {
                            value = getString(R.string.CryptogramSelfTestPass);
                        } else {
                            value = getString(R.string.CryptogramSelfTestFail);
                        }
                        textCell.setTextAndValue("MLS", value, false);
                    }
                    break;
                }
                case 1: {
                    TextInfoPrivacyCell privacyCell = (TextInfoPrivacyCell) holder.itemView;
                    if (position == doubleRatchetInfoRow) {
                        privacyCell.setText(getString(R.string.CryptogramDoubleRatchetInfo));
                    } else if (position == mlsInfoRow) {
                        privacyCell.setText(getString(R.string.CryptogramMLSInfo));
                    } else if (position == selfTestInfoRow) {
                        privacyCell.setText("Runs native self-tests for Double Ratchet and MLS encryption protocols.");
                    }
                    break;
                }
                case 2: {
                    HeaderCell headerCell = (HeaderCell) holder.itemView;
                    if (position == headerRow) {
                        headerCell.setText(getString(R.string.CryptogramSettings));
                    } else if (position == privacyHeaderRow) {
                        headerCell.setText("Privacy & Security");
                    } else if (position == nativeSectionRow) {
                        headerCell.setText(getString(R.string.CryptogramNativeStatus));
                    }
                    break;
                }
                case 3: {
                    TextCheckCell textCheckCell = (TextCheckCell) holder.itemView;
                    if (position == doubleRatchetRow) {
                        textCheckCell.setTextAndCheck(getString(R.string.CryptogramDoubleRatchet), SharedConfig.cryptogramDoubleRatchet, true);
                    } else if (position == mlsRow) {
                        textCheckCell.setTextAndCheck(getString(R.string.CryptogramMLS), SharedConfig.cryptogramMLS, false);
                    } else if (position == hideOnlineRow) {
                        textCheckCell.setTextAndCheck("Hide Online Status", SharedConfig.cryptogramHideOnlineStatus, true);
                    } else if (position == hideTypingRow) {
                        textCheckCell.setTextAndCheck("Hide Typing Indicator", SharedConfig.cryptogramHideTypingIndicator, true);
                    } else if (position == hideReadReceiptsRow) {
                        textCheckCell.setTextAndCheck("Hide Read Receipts", SharedConfig.cryptogramHideReadReceipts, true);
                    } else if (position == stylometryRow) {
                        textCheckCell.setTextAndCheck("Stylometry Shield", SharedConfig.cryptogramStylometryShield, true);
                    } else if (position == antiForensicsRow) {
                        textCheckCell.setTextAndCheck("Anti-Forensics", SharedConfig.cryptogramAntiForensics, true);
                    } else if (position == dpiEvasionRow) {
                        textCheckCell.setTextAndCheck("DPI Evasion", SharedConfig.cryptogramDpiEvasion, true);
                    } else if (position == curatedStickersRow) {
                        textCheckCell.setTextAndCheck("Curated Stickers Only", SharedConfig.cryptogramCuratedStickers, false);
                    }
                    break;
                }
                case 5: {
                    TextCell textCell = (TextCell) holder.itemView;
                    if (position == selfTestButtonRow) {
                        textCell.setText(getString(R.string.CryptogramSelfTest), false);
                    }
                    break;
                }
            }
        }

        @Override
        public int getItemViewType(int position) {
            if (position == nativeStatusRow || position == nativeVersionRow || position == doubleRatchetTestRow || position == mlsTestRow) {
                return 0;
            } else if (position == doubleRatchetInfoRow || position == mlsInfoRow || position == selfTestInfoRow) {
                return 1;
            } else if (position == headerRow || position == privacyHeaderRow || position == nativeSectionRow) {
                return 2;
            } else if (position == doubleRatchetRow || position == mlsRow ||
                       position == hideOnlineRow || position == hideTypingRow ||
                       position == hideReadReceiptsRow || position == stylometryRow ||
                       position == antiForensicsRow || position == dpiEvasionRow ||
                       position == curatedStickersRow) {
                return 3;
            } else if (position == shadowRow || position == privacyShadowRow) {
                return 4;
            } else if (position == selfTestButtonRow) {
                return 5;
            }
            return 0;
        }
    }

    @Override
    public ArrayList<ThemeDescription> getThemeDescriptions() {
        ArrayList<ThemeDescription> themeDescriptions = new ArrayList<>();

        themeDescriptions.add(new ThemeDescription(listView, ThemeDescription.FLAG_CELLBACKGROUNDCOLOR, new Class[]{TextSettingsCell.class, HeaderCell.class, TextCheckCell.class, TextCell.class}, null, null, null, Theme.key_windowBackgroundWhite));
        themeDescriptions.add(new ThemeDescription(fragmentView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundGray));

        themeDescriptions.add(new ThemeDescription(listView, ThemeDescription.FLAG_LISTGLOWCOLOR, null, null, null, null, Theme.key_actionBarDefault));
        themeDescriptions.add(new ThemeDescription(actionBar, ThemeDescription.FLAG_AB_ITEMSCOLOR, null, null, null, null, Theme.key_actionBarDefaultIcon));
        themeDescriptions.add(new ThemeDescription(actionBar, ThemeDescription.FLAG_AB_TITLECOLOR, null, null, null, null, Theme.key_actionBarDefaultTitle));
        themeDescriptions.add(new ThemeDescription(actionBar, ThemeDescription.FLAG_AB_SELECTORCOLOR, null, null, null, null, Theme.key_actionBarDefaultSelector));

        themeDescriptions.add(new ThemeDescription(listView, ThemeDescription.FLAG_SELECTOR, null, null, null, null, Theme.key_listSelector));

        themeDescriptions.add(new ThemeDescription(listView, 0, new Class[]{View.class}, Theme.dividerPaint, null, null, Theme.key_divider));

        themeDescriptions.add(new ThemeDescription(listView, 0, new Class[]{TextSettingsCell.class}, new String[]{"textView"}, null, null, null, Theme.key_windowBackgroundWhiteBlackText));
        themeDescriptions.add(new ThemeDescription(listView, 0, new Class[]{TextSettingsCell.class}, new String[]{"valueTextView"}, null, null, null, Theme.key_windowBackgroundWhiteValueText));

        themeDescriptions.add(new ThemeDescription(listView, 0, new Class[]{HeaderCell.class}, new String[]{"textView"}, null, null, null, Theme.key_windowBackgroundWhiteBlueHeader));

        themeDescriptions.add(new ThemeDescription(listView, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{TextInfoPrivacyCell.class}, null, null, null, Theme.key_windowBackgroundGrayShadow));
        themeDescriptions.add(new ThemeDescription(listView, 0, new Class[]{TextInfoPrivacyCell.class}, new String[]{"textView"}, null, null, null, Theme.key_windowBackgroundWhiteGrayText4));

        themeDescriptions.add(new ThemeDescription(listView, 0, new Class[]{TextCheckCell.class}, new String[]{"textView"}, null, null, null, Theme.key_windowBackgroundWhiteBlackText));
        themeDescriptions.add(new ThemeDescription(listView, 0, new Class[]{TextCheckCell.class}, new String[]{"valueTextView"}, null, null, null, Theme.key_windowBackgroundWhiteGrayText2));
        themeDescriptions.add(new ThemeDescription(listView, 0, new Class[]{TextCheckCell.class}, new String[]{"checkBox"}, null, null, null, Theme.key_switchTrack));
        themeDescriptions.add(new ThemeDescription(listView, 0, new Class[]{TextCheckCell.class}, new String[]{"checkBox"}, null, null, null, Theme.key_switchTrackChecked));

        themeDescriptions.add(new ThemeDescription(listView, 0, new Class[]{TextCell.class}, new String[]{"textView"}, null, null, null, Theme.key_windowBackgroundWhiteBlueText4));

        return themeDescriptions;
    }

    @Override
    public boolean isSupportEdgeToEdge() {
        return true;
    }

    @Override
    public void onInsets(int left, int top, int right, int bottom) {
        listView.setPadding(0, 0, 0, bottom);
        listView.setClipToPadding(false);
    }
}
