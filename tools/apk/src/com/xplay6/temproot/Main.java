package com.xplay6.temproot;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.graphics.drawable.ColorDrawable;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.Editable;
import android.text.InputType;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.util.Log;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.inputmethod.EditorInfo;
import android.widget.BaseAdapter;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/* KernelSU-style shell: a status home page, a searchable app permission page and a
 * grouped settings page, with the daemon log as its own screen.  The allow list is
 * still the product: a row's switch IS the decision, written to disk right away. */
public final class Main extends Activity {

    private static final int PAGE_HOME = 0, PAGE_MODULES = 1, PAGE_APPS = 2, PAGE_SETTINGS = 3;

    private Ui u;
    private final Handler ui = new Handler(Looper.getMainLooper());

    private final List<Chain.Entry> all = new ArrayList<Chain.Entry>();
    private final List<Chain.Entry> rows = new ArrayList<Chain.Entry>();
    private final Set<String> checked = new HashSet<String>();
    private boolean showSystem;
    private boolean appsLoaded, loading;
    private int page = PAGE_HOME;

    private final FrameLayout[] pages = new FrameLayout[4];
    /* 模块页保留在代码里（EscService 开机仍会跑 Modules.bootRun），但导航不再暴露入口。 */
    private final int[] navPages = { PAGE_HOME, PAGE_APPS, PAGE_SETTINGS };
    private final View[] navItems = new View[3];
    private final FrameLayout[] navPills = new FrameLayout[3];
    private final ImageView[] navIcons = new ImageView[3];
    private final TextView[] navLabels = new TextView[3];
    private int[] navGlyphs = { Ui.HOME, Ui.APPS, Ui.SETTINGS };

    private TextView heroTitle, heroDetail, statGrants, statSe, statSu, escalateLabel;
    private FrameLayout heroBadge;
    private ImageView heroIcon;
    private View escalateBtn, refreshBtn;
    private LinearLayout escalateProgress;
    private boolean escalating;
    private LinearLayout homeGrantedList;
    private TextView homeGrantedCount;

    private BaseAdapter adapter;
    private ListView list;
    private EditText search;
    private TextView listSummary, sysToggleSub, emptyView;
    private Ui.Toggle sysToggle;
    private Ui.Toggle adbInputToggle;
    private Ui.Toggle hifiToggle;
    private Ui.Toggle devWarnToggle;
    private Ui.Toggle adbRootToggle;
    private TextView hifiNote;

    private LinearLayout gainRow601, gainRowStock;
    private ImageView gainCheck601, gainCheckStock;
    private TextView gainNote;

    private final List<Modules.ModEntry> mods = new ArrayList<Modules.ModEntry>();
    private BaseAdapter modAdapter;
    private ListView modList;
    private TextView modSummary, modEmpty;
    private boolean modsLoaded, modsLoading;
    private static final int PICK_MODULE = 4242;

    private FrameLayout logOverlay;
    private TextView logBody;
    private ScrollView logScroll;
    private boolean logOpen;

    private final Chain.Log logger = new Chain.Log() {
        @Override
        public void line(final String s) {
            Log.i("TempRoot", s);
            ui.post(new Runnable() {
                @Override
                public void run() {
                    appendLog(s);
                }
            });
        }
    };

    @Override
    protected void onCreate(Bundle saved) {
        super.onCreate(saved);
        u = new Ui(this);
        getWindow().setStatusBarColor(Ui.BG);
        getWindow().setNavigationBarColor(Ui.BG);

        FrameLayout root = new FrameLayout(this);
        root.setBackgroundColor(Ui.BG);

        LinearLayout shell = new LinearLayout(this);
        shell.setOrientation(LinearLayout.VERTICAL);

        FrameLayout host = new FrameLayout(this);
        pages[PAGE_HOME] = new FrameLayout(this);
        pages[PAGE_MODULES] = new FrameLayout(this);
        pages[PAGE_APPS] = new FrameLayout(this);
        pages[PAGE_SETTINGS] = new FrameLayout(this);
        for (int i = 0; i < pages.length; i++) {
            pages[i].setBackgroundColor(Ui.BG);
            host.addView(pages[i], new FrameLayout.LayoutParams(-1, -1));
            pages[i].setVisibility(i == PAGE_HOME ? View.VISIBLE : View.GONE);
        }
        pages[PAGE_HOME].addView(buildHome(), new FrameLayout.LayoutParams(-1, -1));
        pages[PAGE_MODULES].addView(buildModules(), new FrameLayout.LayoutParams(-1, -1));
        pages[PAGE_APPS].addView(buildApps(), new FrameLayout.LayoutParams(-1, -1));
        pages[PAGE_SETTINGS].addView(buildSettings(), new FrameLayout.LayoutParams(-1, -1));

        shell.addView(host, new LinearLayout.LayoutParams(-1, 0, 1f));
        shell.addView(buildNav(), new LinearLayout.LayoutParams(-1, -2));
        root.addView(shell, new FrameLayout.LayoutParams(-1, -1));
        root.addView(buildLogOverlay(), new FrameLayout.LayoutParams(-1, -1));
        setContentView(root);

        styleNav();
        Chain.useToken(this);
        logger.line("xplay6 tmproot " + versionName()
                + " · 仅内存态：重启回到出厂；未提权时任何 PATH 上都没有 su");
        updateGainSettings();
        updateHifiSettings();
        /* 全局 Hi-Fi 不依赖 root，但标志活在 audioserver 里：每次进程起来都按存储的
         * 选择重放一次，重启/音频服务重启后不会悄悄丢掉。 */
        Chain.applyHifiChoice(this, logger);
        rebuild();
        refresh();
        status();
    }

    /* ---------------------------------------------------------------- home */

    private View buildHome() {
        ScrollView sv = new ScrollView(this);
        sv.setFillViewport(true);
        sv.setVerticalScrollBarEnabled(false);
        LinearLayout col = new LinearLayout(this);
        col.setOrientation(LinearLayout.VERTICAL);
        col.setPadding(u.dp(20), u.dp(18), u.dp(20), u.dp(24));
        sv.addView(col, new ScrollView.LayoutParams(-1, -2));

        TextView title = u.heading("xplay6 tmproot", 28, Ui.TEXT);
        col.addView(title);
        TextView sub = u.text("内存态 root · 重启即复原 · v" + versionName(), 13, Ui.MUTED, Ui.REG);
        LinearLayout.LayoutParams subLp = new LinearLayout.LayoutParams(-1, -2);
        subLp.topMargin = u.dp(5);
        col.addView(sub, subLp);

        LinearLayout hero = new LinearLayout(this);
        hero.setOrientation(LinearLayout.VERTICAL);
        hero.setBackground(u.shape(Ui.SURFACE, 24));
        hero.setPadding(u.dp(20), u.dp(20), u.dp(20), u.dp(18));
        LinearLayout.LayoutParams heroLp = new LinearLayout.LayoutParams(-1, -2);
        heroLp.topMargin = u.dp(20);
        col.addView(hero, heroLp);

        LinearLayout statusRow = new LinearLayout(this);
        statusRow.setGravity(Gravity.CENTER_VERTICAL);
        heroBadge = new FrameLayout(this);
        heroBadge.setBackground(u.shape(0x26F2CC7B, 24));
        heroIcon = u.icon(Ui.SHIELD, Ui.AMBER, 24);
        heroBadge.addView(heroIcon);
        statusRow.addView(heroBadge, new LinearLayout.LayoutParams(u.dp(48), u.dp(48)));
        LinearLayout statusText = new LinearLayout(this);
        statusText.setOrientation(LinearLayout.VERTICAL);
        heroTitle = u.heading("正在读取…", 19, Ui.TEXT);
        statusText.addView(heroTitle);
        heroDetail = u.text("正在读取 SELinux 与 su 状态…", 12, Ui.MUTED, Ui.REG);
        heroDetail.setLineSpacing(u.dp(3), 1f);
        LinearLayout.LayoutParams dlp = new LinearLayout.LayoutParams(-1, -2);
        dlp.topMargin = u.dp(4);
        statusText.addView(heroDetail, dlp);
        LinearLayout.LayoutParams stlp = new LinearLayout.LayoutParams(0, -2, 1f);
        stlp.leftMargin = u.dp(14);
        statusRow.addView(statusText, stlp);
        hero.addView(statusRow);

        LinearLayout stats = new LinearLayout(this);
        stats.setOrientation(LinearLayout.HORIZONTAL);
        statGrants = u.text("—", 17, Ui.TEXT, Ui.MED);
        statSe = u.text("—", 17, Ui.TEXT, Ui.MED);
        statSu = u.text("—", 17, Ui.TEXT, Ui.MED);
        stats.addView(statCell("已授权应用", statGrants), new LinearLayout.LayoutParams(0, -2, 1f));
        stats.addView(statCell("SELinux", statSe), new LinearLayout.LayoutParams(0, -2, 1f));
        stats.addView(statCell("su", statSu), new LinearLayout.LayoutParams(0, -2, 1f));
        LinearLayout.LayoutParams statsLp = new LinearLayout.LayoutParams(-1, -2);
        statsLp.topMargin = u.dp(20);
        hero.addView(stats, statsLp);

        LinearLayout actions = new LinearLayout(this);
        actions.setGravity(Gravity.CENTER_VERTICAL);
        escalateBtn = u.text("提权", 15, Ui.ON_PRIMARY, Ui.MED);
        ((TextView) escalateBtn).setGravity(Gravity.CENTER);
        escalateLabel = (TextView) escalateBtn;
        escalateBtn.setBackground(u.press(u.shape(Ui.PRIMARY, 24)));
        escalateBtn.setClickable(true);
        escalateBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                escalate();
            }
        });
        actions.addView(escalateBtn, new LinearLayout.LayoutParams(0, u.dp(48), 1f));
        refreshBtn = u.text("刷新", 14, Ui.PRIMARY, Ui.MED);
        ((TextView) refreshBtn).setGravity(Gravity.CENTER);
        refreshBtn.setBackground(u.press(u.shape(0x00000000, 24, 1, Ui.OUTLINE)));
        refreshBtn.setClickable(true);
        refreshBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                refresh();
                status();
            }
        });
        LinearLayout.LayoutParams rlp = new LinearLayout.LayoutParams(u.dp(92), u.dp(48));
        rlp.leftMargin = u.dp(10);
        actions.addView(refreshBtn, rlp);
        LinearLayout.LayoutParams actLp = new LinearLayout.LayoutParams(-1, -2);
        actLp.topMargin = u.dp(18);
        hero.addView(actions, actLp);

        escalateProgress = new LinearLayout(this);
        escalateProgress.setGravity(Gravity.CENTER_VERTICAL);
        ProgressBar pb = new ProgressBar(this, null, android.R.attr.progressBarStyleSmall);
        try {
            pb.getIndeterminateDrawable().setTint(Ui.PRIMARY);
        } catch (Throwable ignore) {
        }
        LinearLayout.LayoutParams pblp = new LinearLayout.LayoutParams(u.dp(18), u.dp(18));
        pblp.rightMargin = u.dp(8);
        escalateProgress.addView(pb, pblp);
        escalateProgress.addView(u.text("正在执行提权链，过程写在「运行日志」里", 12, Ui.MUTED, Ui.REG));
        escalateProgress.setVisibility(View.GONE);
        LinearLayout.LayoutParams elp = new LinearLayout.LayoutParams(-1, -2);
        elp.topMargin = u.dp(12);
        hero.addView(escalateProgress, elp);

        LinearLayout grantedCard = new LinearLayout(this);
        grantedCard.setOrientation(LinearLayout.VERTICAL);
        grantedCard.setBackground(u.shape(Ui.SURFACE, 18));
        grantedCard.setClipToOutline(true);
        grantedCard.setPadding(u.dp(16), u.dp(12), u.dp(16), u.dp(8));
        LinearLayout grantedHead = new LinearLayout(this);
        grantedHead.setGravity(Gravity.CENTER_VERTICAL);
        grantedHead.addView(u.text("已授权应用", 14, Ui.TEXT, Ui.MED),
                new LinearLayout.LayoutParams(0, -2, 1f));
        homeGrantedCount = u.text("", 12, Ui.MUTED, Ui.REG);
        grantedHead.addView(homeGrantedCount);
        TextView manage = u.text("管理", 12, Ui.PRIMARY, Ui.MED);
        LinearLayout.LayoutParams mlp0 = new LinearLayout.LayoutParams(-2, -2);
        mlp0.leftMargin = u.dp(8);
        grantedHead.addView(manage, mlp0);
        ImageView manageChevron = u.icon(Ui.CHEVRON, Ui.PRIMARY, 14);
        LinearLayout.LayoutParams mclp = new LinearLayout.LayoutParams(u.dp(14), u.dp(14));
        mclp.leftMargin = u.dp(2);
        grantedHead.addView(manageChevron, mclp);
        grantedHead.setBackground(u.press(u.shape(0x00000000, 0)));
        grantedHead.setClickable(true);
        grantedHead.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                showPage(PAGE_APPS);
            }
        });
        grantedCard.addView(grantedHead, new LinearLayout.LayoutParams(-1, -2));
        homeGrantedList = new LinearLayout(this);
        homeGrantedList.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams hglp = new LinearLayout.LayoutParams(-1, -2);
        hglp.topMargin = u.dp(4);
        grantedCard.addView(homeGrantedList, hglp);
        LinearLayout.LayoutParams gcLp = new LinearLayout.LayoutParams(-1, -2);
        gcLp.topMargin = u.dp(14);
        col.addView(grantedCard, gcLp);

        LinearLayout logRow = new LinearLayout(this);
        logRow.setGravity(Gravity.CENTER_VERTICAL);
        logRow.setBackground(u.press(u.shape(Ui.SURFACE, 18)));
        logRow.setPadding(u.dp(16), u.dp(14), u.dp(14), u.dp(14));
        logRow.addView(u.icon(Ui.LOG, Ui.PRIMARY, 20),
                new LinearLayout.LayoutParams(u.dp(20), u.dp(20)));
        LinearLayout logText = new LinearLayout(this);
        logText.setOrientation(LinearLayout.VERTICAL);
        logText.addView(u.text("运行日志", 14, Ui.TEXT, Ui.MED));
        TextView logSub = u.text("提权链每一步都记在这里", 12, Ui.MUTED, Ui.REG);
        LinearLayout.LayoutParams lslp = new LinearLayout.LayoutParams(-1, -2);
        lslp.topMargin = u.dp(2);
        logText.addView(logSub, lslp);
        LinearLayout.LayoutParams ltlp = new LinearLayout.LayoutParams(0, -2, 1f);
        ltlp.leftMargin = u.dp(14);
        logRow.addView(logText, ltlp);
        logRow.addView(u.icon(Ui.CHEVRON, Ui.MUTED, 16),
                new LinearLayout.LayoutParams(u.dp(16), u.dp(16)));
        logRow.setClickable(true);
        logRow.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                openLog();
            }
        });
        LinearLayout.LayoutParams logLp = new LinearLayout.LayoutParams(-1, -2);
        logLp.topMargin = u.dp(14);
        col.addView(logRow, logLp);

        LinearLayout info = new LinearLayout(this);
        info.setBackground(u.shape(Ui.SURFACE, 18, 1, Ui.OUTLINE));
        info.setPadding(u.dp(16), u.dp(14), u.dp(16), u.dp(14));
        info.addView(u.icon(Ui.INFO, Ui.PRIMARY, 18),
                new LinearLayout.LayoutParams(u.dp(18), u.dp(18)));
        LinearLayout infoText = new LinearLayout(this);
        infoText.setOrientation(LinearLayout.VERTICAL);
        infoText.addView(u.text("仅本次开机有效", 13, Ui.TEXT, Ui.MED));
        TextView infoBody = u.text("提权只改运行内存与 SELinux 运行表，不刷机、不写分区；重启后自动回到出厂状态。",
                12, Ui.MUTED, Ui.REG);
        infoBody.setLineSpacing(u.dp(3), 1f);
        LinearLayout.LayoutParams iblp = new LinearLayout.LayoutParams(-1, -2);
        iblp.topMargin = u.dp(3);
        infoText.addView(infoBody, iblp);
        LinearLayout.LayoutParams itlp = new LinearLayout.LayoutParams(0, -2, 1f);
        itlp.leftMargin = u.dp(12);
        info.addView(infoText, itlp);
        LinearLayout.LayoutParams infoLp = new LinearLayout.LayoutParams(-1, -2);
        infoLp.topMargin = u.dp(14);
        col.addView(info, infoLp);

        return sv;
    }

    private LinearLayout statCell(String label, TextView value) {
        LinearLayout c = new LinearLayout(this);
        c.setOrientation(LinearLayout.VERTICAL);
        c.addView(value);
        TextView l = u.text(label, 11, Ui.MUTED, Ui.REG);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-2, -2);
        lp.topMargin = u.dp(3);
        c.addView(l, lp);
        return c;
    }

    /* ---------------------------------------------------------------- apps */

    private View buildApps() {
        LinearLayout pageRoot = new LinearLayout(this);
        pageRoot.setOrientation(LinearLayout.VERTICAL);

        LinearLayout head = new LinearLayout(this);
        head.setOrientation(LinearLayout.VERTICAL);
        head.setPadding(u.dp(20), u.dp(18), u.dp(20), 0);
        head.addView(u.heading("应用授权", 28, Ui.TEXT));
        TextView sub = u.text("点按一行即写入授权名单，不需要保存", 13, Ui.MUTED, Ui.REG);
        LinearLayout.LayoutParams subLp = new LinearLayout.LayoutParams(-1, -2);
        subLp.topMargin = u.dp(5);
        head.addView(sub, subLp);

        LinearLayout searchWrap = new LinearLayout(this);
        searchWrap.setGravity(Gravity.CENTER_VERTICAL);
        searchWrap.setBackground(u.shape(Ui.SURFACE_HI, 14));
        ImageView si = u.icon(Ui.SEARCH, Ui.MUTED, 18);
        LinearLayout.LayoutParams silp = new LinearLayout.LayoutParams(u.dp(18), u.dp(18));
        silp.leftMargin = u.dp(14);
        silp.rightMargin = u.dp(10);
        searchWrap.addView(si, silp);
        search = new EditText(this);
        search.setSingleLine(true);
        search.setBackground(null);
        search.setGravity(Gravity.CENTER_VERTICAL);
        search.setHint("搜索应用或包名");
        search.setHintTextColor(Ui.MUTED);
        search.setTextColor(Ui.TEXT);
        search.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14);
        search.setTypeface(Ui.REG);
        search.setInputType(InputType.TYPE_CLASS_TEXT);
        search.setImeOptions(EditorInfo.IME_ACTION_SEARCH);
        search.setPadding(0, 0, u.dp(12), 0);
        search.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int st, int c, int a) {
            }

            @Override
            public void onTextChanged(CharSequence s, int st, int b, int c) {
            }

            @Override
            public void afterTextChanged(Editable s) {
                rebuild();
            }
        });
        searchWrap.addView(search, new LinearLayout.LayoutParams(0, u.dp(46), 1f));
        LinearLayout.LayoutParams swlp = new LinearLayout.LayoutParams(-1, u.dp(46));
        swlp.topMargin = u.dp(16);
        head.addView(searchWrap, swlp);

        final LinearLayout sys = new LinearLayout(this);
        sys.setGravity(Gravity.CENTER_VERTICAL);
        sys.setBackground(u.shape(Ui.SURFACE, 16));
        sys.setPadding(u.dp(16), u.dp(12), u.dp(14), u.dp(12));
        LinearLayout sysText = new LinearLayout(this);
        sysText.setOrientation(LinearLayout.VERTICAL);
        sysText.addView(u.text("显示系统应用", 14, Ui.TEXT, Ui.MED));
        sysToggleSub = u.text("预装应用默认隐藏", 12, Ui.MUTED, Ui.REG);
        LinearLayout.LayoutParams sslp = new LinearLayout.LayoutParams(-1, -2);
        sslp.topMargin = u.dp(2);
        sysText.addView(sysToggleSub, sslp);
        sys.addView(sysText, new LinearLayout.LayoutParams(0, -2, 1f));
        sysToggle = new Ui.Toggle(this, u);
        sysToggle.setChecked(showSystem);
        sysToggle.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                toggleSystem();
            }
        });
        sys.addView(sysToggle, new LinearLayout.LayoutParams(u.dp(52), u.dp(32)));
        sys.setClickable(true);
        sys.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                toggleSystem();
            }
        });
        LinearLayout.LayoutParams sysLp = new LinearLayout.LayoutParams(-1, -2);
        sysLp.topMargin = u.dp(12);
        head.addView(sys, sysLp);

        listSummary = u.text("正在读取应用列表…", 12, Ui.MUTED, Ui.REG);
        LinearLayout.LayoutParams sumLp = new LinearLayout.LayoutParams(-1, -2);
        sumLp.topMargin = u.dp(14);
        sumLp.leftMargin = u.dp(4);
        sumLp.bottomMargin = u.dp(2);
        head.addView(listSummary, sumLp);
        pageRoot.addView(head, new LinearLayout.LayoutParams(-1, -2));

        FrameLayout listHost = new FrameLayout(this);
        list = new ListView(this);
        list.setBackgroundColor(0x00000000);
        list.setCacheColorHint(0x00000000);
        list.setDivider(new ColorDrawable(0xFF26242C));
        list.setDividerHeight(1);
        list.setSelector(new ColorDrawable(0x00000000));
        list.setVerticalScrollBarEnabled(false);
        list.setOverScrollMode(View.OVER_SCROLL_NEVER);
        list.setFadingEdgeLength(0);
        list.setPadding(u.dp(20), u.dp(8), u.dp(20), u.dp(16));
        list.setClipToPadding(false);
        adapter = new BaseAdapter() {
            @Override
            public int getCount() {
                return rows.size();
            }

            @Override
            public Object getItem(int pos) {
                return rows.get(pos);
            }

            @Override
            public long getItemId(int pos) {
                return pos;
            }

            @Override
            public View getView(int pos, View cv, ViewGroup parent) {
                return appRow(pos, cv, rows.get(pos));
            }
        };
        list.setAdapter(adapter);
        emptyView = u.text("正在读取应用列表…", 13, Ui.MUTED, Ui.REG);
        emptyView.setGravity(Gravity.CENTER);
        emptyView.setPadding(u.dp(20), u.dp(20), u.dp(20), u.dp(20));
        listHost.addView(list, new FrameLayout.LayoutParams(-1, -1));
        listHost.addView(emptyView, new FrameLayout.LayoutParams(-1, -1));
        list.setEmptyView(emptyView);
        pageRoot.addView(listHost, new LinearLayout.LayoutParams(-1, 0, 1f));
        return pageRoot;
    }

    private static final class RowHolder {
        ImageView icon;
        TextView name, detail;
        Ui.Toggle toggle;
    }

    private View appRow(int pos, View cv, final Chain.Entry e) {
        LinearLayout row;
        RowHolder h;
        if (cv instanceof LinearLayout && ((LinearLayout) cv).getTag() instanceof RowHolder) {
            row = (LinearLayout) cv;
            h = (RowHolder) row.getTag();
        } else {
            row = new LinearLayout(this);
            row.setOrientation(LinearLayout.HORIZONTAL);
            row.setGravity(Gravity.CENTER_VERTICAL);
            row.setMinimumHeight(u.dp(68));
            row.setPadding(u.dp(16), u.dp(10), u.dp(14), u.dp(10));
            h = new RowHolder();
            h.icon = new ImageView(this);
            h.icon.setScaleType(ImageView.ScaleType.FIT_CENTER);
            LinearLayout.LayoutParams iconLp = new LinearLayout.LayoutParams(u.dp(40), u.dp(40));
            iconLp.rightMargin = u.dp(14);
            row.addView(h.icon, iconLp);

            LinearLayout col = new LinearLayout(this);
            col.setOrientation(LinearLayout.VERTICAL);
            col.setLayoutParams(new LinearLayout.LayoutParams(0, -2, 1f));
            h.name = u.text("", 15, Ui.TEXT, Ui.MED);
            h.name.setSingleLine(true);
            h.name.setEllipsize(TextUtils.TruncateAt.END);
            col.addView(h.name, new LinearLayout.LayoutParams(-1, -2));
            h.detail = u.text("", 12, Ui.MUTED, Ui.REG);
            h.detail.setSingleLine(true);
            h.detail.setEllipsize(TextUtils.TruncateAt.END);
            LinearLayout.LayoutParams detLp = new LinearLayout.LayoutParams(-1, -2);
            detLp.topMargin = u.dp(3);
            col.addView(h.detail, detLp);
            row.addView(col);

            h.toggle = new Ui.Toggle(this, u);
            h.toggle.setClickable(false);
            h.toggle.setFocusable(false);
            LinearLayout.LayoutParams toggleLp = new LinearLayout.LayoutParams(u.dp(52), u.dp(32));
            toggleLp.leftMargin = u.dp(8);
            row.addView(h.toggle, toggleLp);
            row.setTag(h);
        }

        boolean first = pos == 0;
        boolean last = pos == rows.size() - 1;
        row.setBackground(u.press(u.groupBg(first ? 20 : 0, last ? 20 : 0)));

        boolean on = checked.contains(e.pkg);
        h.name.setText(e.uid == android.os.Process.myUid() ? e.label + "（本应用）" : e.label);
        h.detail.setText((e.system ? "系统 · " : "") + "uid " + e.uid + " · " + e.pkg);
        try {
            h.icon.setImageDrawable(getPackageManager().getApplicationIcon(e.pkg));
        } catch (Throwable t) {
            h.icon.setImageDrawable(u.shape(Ui.SURFACE_HI, 12));
        }
        h.toggle.setChecked(on);
        row.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                toggle(e);
            }
        });
        return row;
    }

    private void toggleSystem() {
        showSystem = !showSystem;
        if (sysToggle != null)
            sysToggle.setChecked(showSystem);
        rebuild();
    }

    private void toggle(final Chain.Entry e) {
        if (e.uid == android.os.Process.myUid()) {
            toast("本应用始终保持授权，否则没人能再改这张表");
            return;
        }
        if (e.uid == Chain.SHELL_UID) {
            /* com.android.shell 这一行与设置页的「ADB root 权限」是同一枚 uid：点它等于点那个
             * 开关，走同一条显式增删的路。整体重写（saveSelection）会照 checked 的旧像把名单
             * 覆写回去，而那个像可能比设置页的开关旧一个刷新。目标态照这一行现在显示的样子取
             * ——用户看到的是什么，点的就是什么。 */
            toggleAdbRoot(!checked.contains(e.pkg));
            return;
        }
        final boolean on;
        if (checked.contains(e.pkg)) {
            checked.remove(e.pkg);
            on = false;
        } else {
            checked.add(e.pkg);
            on = true;
        }
        rebuild();

        new Thread(new Runnable() {
            @Override
            public void run() {
                final boolean ok = Chain.saveSelection(Main.this, all, new ArrayList<String>(checked));
                final String now = Chain.root("id");
                ui.post(new Runnable() {
                    @Override
                    public void run() {
                        logger.line((on ? "已授权 " : "已撤销 ") + e.pkg + "  uid=" + e.uid
                                + "  saved=" + ok + "  文件=" + Chain.grantsFile(Main.this).getAbsolutePath());
                        logger.line("守护进程现在对我说的身份: " + now);
                        if (!ok)
                            toast("保存授权名单失败，详见运行日志");
                        updateHomeStats();
                    }
                });
            }
        }).start();
    }

    private void rebuild() {
        if (adapter == null)
            return;
        String q = search == null ? "" : search.getText().toString().trim().toLowerCase(Locale.US);
        List<Chain.Entry> filtered = new ArrayList<Chain.Entry>();
        for (Chain.Entry e : all) {
            boolean granted = checked.contains(e.pkg);
            if (e.system && !granted && !showSystem && q.length() == 0)
                continue;
            if (q.length() > 0) {
                String label = e.label == null ? "" : e.label.toLowerCase(Locale.US);
                if (!label.contains(q) && !e.pkg.toLowerCase(Locale.US).contains(q))
                    continue;
            }
            filtered.add(e);
        }
        Collections.sort(filtered, new Comparator<Chain.Entry>() {
            @Override
            public int compare(Chain.Entry a, Chain.Entry b) {
                return a.label.compareToIgnoreCase(b.label);
            }
        });
        rows.clear();
        rows.addAll(filtered);
        adapter.notifyDataSetChanged();

        int sysTotal = 0;
        for (Chain.Entry e : all)
            if (e.system)
                sysTotal++;
        if (sysToggleSub != null)
            sysToggleSub.setText("预装应用共 " + sysTotal + " 个 · " + (showSystem ? "当前显示" : "当前隐藏"));
        if (listSummary != null) {
            if (!appsLoaded)
                listSummary.setText("正在读取应用列表…");
            else
                listSummary.setText("已授权 " + checked.size() + " 个应用 · 列表 " + filtered.size() + " 项"
                        + (q.length() > 0 ? " · 搜索「" + search.getText().toString().trim() + "」" : ""));
        }
        if (emptyView != null)
            emptyView.setText(!appsLoaded ? "正在读取应用列表…"
                    : q.length() > 0 ? "没有匹配的应用" : "没有可显示的应用");
        updateHomeStats();
    }

    /* -------------------------------------------------------------- modules */

    private View buildModules() {
        LinearLayout pageRoot = new LinearLayout(this);
        pageRoot.setOrientation(LinearLayout.VERTICAL);

        LinearLayout head = new LinearLayout(this);
        head.setOrientation(LinearLayout.VERTICAL);
        head.setPadding(u.dp(20), u.dp(18), u.dp(20), 0);
        head.addView(u.heading("模块", 28, Ui.TEXT));
        TextView sub = u.text("Magisk 格式模块包（zip）· 挂进 /system · 重启失效", 13, Ui.MUTED, Ui.REG);
        LinearLayout.LayoutParams subLp = new LinearLayout.LayoutParams(-1, -2);
        subLp.topMargin = u.dp(5);
        head.addView(sub, subLp);

        TextView installBtn = u.text("安装模块 (zip)", 14, Ui.ON_PRIMARY, Ui.MED);
        installBtn.setGravity(Gravity.CENTER);
        installBtn.setBackground(u.press(u.shape(Ui.PRIMARY, 24)));
        installBtn.setClickable(true);
        installBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                pickModule();
            }
        });
        LinearLayout.LayoutParams ibLp = new LinearLayout.LayoutParams(-1, u.dp(46));
        ibLp.topMargin = u.dp(16);
        head.addView(installBtn, ibLp);

        // The Magisk runtime ships inside the APK (assets/magisk_runtime.zip),
        // so the user does not have to hunt for the zip file.  It installs the
        // same way: /data/adb/modules/magisk_runtime, and the boot-time chain
        // starts the daemon through the module's service.sh.
        TextView magiskBtn = u.text("安装内置 Magisk 运行时", 14, Ui.ON_PRIMARY, Ui.MED);
        magiskBtn.setGravity(Gravity.CENTER);
        magiskBtn.setBackground(u.press(u.shape(Ui.PRIMARY, 24)));
        magiskBtn.setClickable(true);
        magiskBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                installBundledMagisk();
            }
        });
        LinearLayout.LayoutParams mbLp = new LinearLayout.LayoutParams(-1, u.dp(46));
        mbLp.topMargin = u.dp(10);
        head.addView(magiskBtn, mbLp);

        modSummary = u.text("正在读取模块列表…", 12, Ui.MUTED, Ui.REG);
        LinearLayout.LayoutParams sumLp = new LinearLayout.LayoutParams(-1, -2);
        sumLp.topMargin = u.dp(14);
        sumLp.leftMargin = u.dp(4);
        sumLp.bottomMargin = u.dp(2);
        head.addView(modSummary, sumLp);
        pageRoot.addView(head, new LinearLayout.LayoutParams(-1, -2));

        FrameLayout listHost = new FrameLayout(this);
        modList = new ListView(this);
        modList.setBackgroundColor(0x00000000);
        modList.setCacheColorHint(0x00000000);
        modList.setDivider(new ColorDrawable(0xFF26242C));
        modList.setDividerHeight(1);
        modList.setSelector(new ColorDrawable(0x00000000));
        modList.setVerticalScrollBarEnabled(false);
        modList.setOverScrollMode(View.OVER_SCROLL_NEVER);
        modList.setFadingEdgeLength(0);
        modList.setPadding(u.dp(20), u.dp(8), u.dp(20), u.dp(16));
        modList.setClipToPadding(false);
        modAdapter = new BaseAdapter() {
            @Override
            public int getCount() {
                return mods.size();
            }

            @Override
            public Object getItem(int pos) {
                return mods.get(pos);
            }

            @Override
            public long getItemId(int pos) {
                return pos;
            }

            @Override
            public View getView(int pos, View cv, ViewGroup parent) {
                return modRow(pos, cv, mods.get(pos));
            }
        };
        modList.setAdapter(modAdapter);
        modEmpty = u.text("还没有安装任何模块", 13, Ui.MUTED, Ui.REG);
        modEmpty.setGravity(Gravity.CENTER);
        modEmpty.setPadding(u.dp(20), u.dp(20), u.dp(20), u.dp(20));
        listHost.addView(modList, new FrameLayout.LayoutParams(-1, -1));
        listHost.addView(modEmpty, new FrameLayout.LayoutParams(-1, -1));
        modList.setEmptyView(modEmpty);
        pageRoot.addView(listHost, new LinearLayout.LayoutParams(-1, 0, 1f));
        return pageRoot;
    }

    private static final class ModRowHolder {
        TextView name, detail, desc;
        Ui.Toggle toggle;
    }

    private View modRow(int pos, View cv, final Modules.ModEntry e) {
        LinearLayout row;
        ModRowHolder h;
        if (cv instanceof LinearLayout && ((LinearLayout) cv).getTag() instanceof ModRowHolder) {
            row = (LinearLayout) cv;
            h = (ModRowHolder) row.getTag();
        } else {
            row = new LinearLayout(this);
            row.setOrientation(LinearLayout.HORIZONTAL);
            row.setGravity(Gravity.CENTER_VERTICAL);
            row.setMinimumHeight(u.dp(72));
            row.setPadding(u.dp(16), u.dp(10), u.dp(14), u.dp(10));
            h = new ModRowHolder();

            LinearLayout col = new LinearLayout(this);
            col.setOrientation(LinearLayout.VERTICAL);
            col.setLayoutParams(new LinearLayout.LayoutParams(0, -2, 1f));
            h.name = u.text("", 15, Ui.TEXT, Ui.MED);
            h.name.setSingleLine(true);
            h.name.setEllipsize(TextUtils.TruncateAt.END);
            col.addView(h.name, new LinearLayout.LayoutParams(-1, -2));
            h.detail = u.text("", 12, Ui.MUTED, Ui.REG);
            h.detail.setSingleLine(true);
            h.detail.setEllipsize(TextUtils.TruncateAt.END);
            LinearLayout.LayoutParams detLp = new LinearLayout.LayoutParams(-1, -2);
            detLp.topMargin = u.dp(3);
            col.addView(h.detail, detLp);
            h.desc = u.text("", 11, Ui.MUTED, Ui.REG);
            h.desc.setSingleLine(true);
            h.desc.setEllipsize(TextUtils.TruncateAt.END);
            LinearLayout.LayoutParams descLp = new LinearLayout.LayoutParams(-1, -2);
            descLp.topMargin = u.dp(2);
            col.addView(h.desc, descLp);
            row.addView(col);

            h.toggle = new Ui.Toggle(this, u);
            h.toggle.setClickable(false);
            h.toggle.setFocusable(false);
            LinearLayout.LayoutParams toggleLp = new LinearLayout.LayoutParams(u.dp(52), u.dp(32));
            toggleLp.leftMargin = u.dp(8);
            row.addView(h.toggle, toggleLp);
            row.setTag(h);
        }

        boolean first = pos == 0;
        boolean last = pos == mods.size() - 1;
        row.setBackground(u.press(u.groupBg(first ? 20 : 0, last ? 20 : 0)));

        h.name.setText(e.name.isEmpty() ? e.dir : e.name);
        h.name.setTextColor(e.enabled ? Ui.TEXT : Ui.MUTED);
        h.detail.setText((e.enabled ? "" : "已停用 · ")
                + "v" + (e.version.isEmpty() ? "?" : e.version)
                + (e.author.isEmpty() ? "" : " · " + e.author)
                + " · " + e.dir);
        h.desc.setText(e.description);
        h.desc.setVisibility(e.description.isEmpty() ? View.GONE : View.VISIBLE);
        h.toggle.setChecked(e.enabled);
        row.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                toggleMod(e);
            }
        });
        row.setOnLongClickListener(new View.OnLongClickListener() {
            @Override
            public boolean onLongClick(View v) {
                confirmUninstall(e);
                return true;
            }
        });
        return row;
    }

    private void refreshModules() {
        if (modsLoading)
            return;
        modsLoading = true;
        new Thread(new Runnable() {
            @Override
            public void run() {
                final List<Modules.ModEntry> got = Modules.list(Main.this);
                ui.post(new Runnable() {
                    @Override
                    public void run() {
                        modsLoading = false;
                        modsLoaded = true;
                        mods.clear();
                        mods.addAll(got);
                        modRebuild();
                        if (Modules.lastError != null)
                            toast("读模块列表失败：" + Modules.lastError);
                    }
                });
            }
        }).start();
    }

    private void modRebuild() {
        if (modAdapter == null)
            return;
        modAdapter.notifyDataSetChanged();
        int on = 0;
        for (Modules.ModEntry e : mods)
            if (e.enabled)
                on++;
        if (modSummary != null)
            modSummary.setText(!modsLoaded ? "正在读取模块列表…"
                    : mods.isEmpty() ? "还没有安装任何模块"
                    : "共 " + mods.size() + " 个 · 启用 " + on + " 个");
        if (modEmpty != null)
            modEmpty.setText(!modsLoaded ? "正在读取模块列表…"
                    : "还没有安装任何模块\n点上面的按钮选一个 Magisk 格式的 zip");
    }

    /** Toggle is applied remotely first; the list refresh then shows the truth
     *  from the device (a failed toggle leaves the switch where it was). */
    private void toggleMod(final Modules.ModEntry e) {
        final boolean on = !e.enabled;
        toast((on ? "正在启用 " : "正在停用 ") + e.dir + " …");
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    Modules.setEnabled(Main.this, e.dir, on, logger);
                    ui.post(new Runnable() {
                        @Override
                        public void run() {
                            refreshModules();
                        }
                    });
                } catch (final Throwable t) {
                    logger.line("toggle " + e.dir + " failed: " + t);
                    ui.post(new Runnable() {
                        @Override
                        public void run() {
                            toast((on ? "启用" : "停用") + "失败：" + t);
                            refreshModules();
                        }
                    });
                }
            }
        }).start();
    }

    private void confirmUninstall(final Modules.ModEntry e) {
        new AlertDialog.Builder(this)
                .setTitle("卸载模块")
                .setMessage("从 /system 摘除并删除「"
                        + (e.name.isEmpty() ? e.dir : e.name) + "」（" + e.dir + "）？\n此操作不能撤销。")
                .setPositiveButton("卸载", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface d, int w) {
                        doUninstall(e);
                    }
                })
                .setNegativeButton("取消", null)
                .show();
    }

    private void doUninstall(final Modules.ModEntry e) {
        toast("正在卸载 " + e.dir + " …");
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    Modules.uninstall(Main.this, e.dir, logger);
                    ui.post(new Runnable() {
                        @Override
                        public void run() {
                            toast("已卸载 " + e.dir);
                            refreshModules();
                        }
                    });
                } catch (final Throwable t) {
                    logger.line("uninstall " + e.dir + " failed: " + t);
                    ui.post(new Runnable() {
                        @Override
                        public void run() {
                            toast("卸载失败：" + t);
                            refreshModules();
                        }
                    });
                }
            }
        }).start();
    }

    private void pickModule() {
        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType("*/*");
        startActivityForResult(i, PICK_MODULE);
    }

    /** Install the Magisk runtime module that ships inside this APK.
     *
     * Same install path as a zip picked through SAF, but the zip comes from
     * assets/magisk_runtime.zip.  Afterwards the module's service.sh is what
     * starts the Magisk daemon at boot; the module page then shows it like
     * any other module. */
    private void installBundledMagisk() {
        toast("正在安装内置 Magisk 运行时…");
        logger.line("--- 安装内置 Magisk 运行时模块 ---");
        new Thread(new Runnable() {
            @Override
            public void run() {
                final String name;
                try {
                    name = Modules.installBundled(Main.this, logger);
                } catch (final Throwable t) {
                    logger.line("Magisk 运行时安装失败: " + t);
                    ui.post(new Runnable() {
                        @Override
                        public void run() {
                            toast("安装失败：" + t.getMessage());
                        }
                    });
                    return;
                }
                ui.post(new Runnable() {
                    @Override
                    public void run() {
                        toast("已安装 " + name + "，重启后自动启动");
                        refreshModules();
                    }
                });
            }
        }).start();
    }

    @Override
    protected void onActivityResult(int req, int res, Intent data) {
        if (req != PICK_MODULE || res != RESULT_OK || data == null || data.getData() == null) {
            super.onActivityResult(req, res, data);
            return;
        }
        final Uri uri = data.getData();
        toast("正在安装模块…");
        logger.line("--- 安装模块 " + uri + " ---");
        new Thread(new Runnable() {
            @Override
            public void run() {
                final String name;
                try {
                    name = Modules.install(Main.this, uri, logger);
                } catch (final Throwable t) {
                    logger.line("模块安装失败: " + t);
                    ui.post(new Runnable() {
                        @Override
                        public void run() {
                            toast("安装失败：" + t.getMessage());
                        }
                    });
                    return;
                }
                ui.post(new Runnable() {
                    @Override
                    public void run() {
                        toast("已安装 " + name + "，挂载已生效");
                        refreshModules();
                    }
                });
            }
        }).start();
    }

    /* ------------------------------------------------------------ settings */

    private View buildSettings() {
        ScrollView sv = new ScrollView(this);
        sv.setFillViewport(true);
        sv.setVerticalScrollBarEnabled(false);
        final LinearLayout col = new LinearLayout(this);
        col.setOrientation(LinearLayout.VERTICAL);
        col.setPadding(u.dp(20), u.dp(18), u.dp(20), u.dp(28));
        sv.addView(col, new ScrollView.LayoutParams(-1, -2));

        col.addView(u.heading("设置", 28, Ui.TEXT));
        TextView sub = u.text("授权、USB 调试、音频与诊断", 13, Ui.MUTED, Ui.REG);
        LinearLayout.LayoutParams subLp = new LinearLayout.LayoutParams(-1, -2);
        subLp.topMargin = u.dp(5);
        col.addView(sub, subLp);

        addSection(col, "授权与安全");
        LinearLayout sec1 = newCard();
        LinearLayout adbRootRow = settingRow(Ui.TERMINAL, "ADB root 权限",
                "授权 uid 2000：电脑上 adb shell 后 su 即得 root",
                null, Ui.TEXT, false, new Runnable() {
                    @Override
                    public void run() {
                        toggleAdbRoot();
                    }
                });
        adbRootToggle = new Ui.Toggle(this, u);
        adbRootToggle.setChecked(Chain.shellGranted(this));
        adbRootToggle.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                toggleAdbRoot();
            }
        });
        adbRootRow.addView(adbRootToggle, new LinearLayout.LayoutParams(u.dp(52), u.dp(32)));
        sec1.addView(adbRootRow);
        sec1.addView(divider());
        sec1.addView(settingRow(Ui.TRASH, "撤销全部授权", "保留本应用，其它应用立即失效",
                null, Ui.RED, false, new Runnable() {
                    @Override
                    public void run() {
                        revokeAll();
                    }
                }));
        sec1.addView(divider());
        sec1.addView(settingRow(Ui.TERMINAL, "测试 su 名字闸", "检查应用侧的 su 路径闸是否打开",
                null, Ui.TEXT, true, new Runnable() {
                    @Override
                    public void run() {
                        probeSuName();
                    }
                }));
        col.addView(sec1, cardLp());

        addSection(col, "USB 调试");
        LinearLayout secAdb = newCard();
        LinearLayout adbRow = settingRow(-1, "USB 模拟点击",
                "提权成功后自动写入系统开关，不需要登录 vivo 账号",
                null, Ui.TEXT, false, new Runnable() {
                    @Override
                    public void run() {
                        toggleAdbInput();
                    }
                });
        adbInputToggle = new Ui.Toggle(this, u);
        adbInputToggle.setChecked(Chain.adbInputChoice(this));
        adbInputToggle.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                toggleAdbInput();
            }
        });
        adbRow.addView(adbInputToggle, new LinearLayout.LayoutParams(u.dp(52), u.dp(32)));
        secAdb.addView(adbRow);
        col.addView(secAdb, cardLp());

        addSection(col, "系统提示");
        LinearLayout secWarn = newCard();
        LinearLayout warnRow = settingRow(-1, "隐藏开发模式警告",
                "只去掉状态栏那条黄条；开发者选项和 USB 调试照旧",
                null, Ui.TEXT, false, new Runnable() {
                    @Override
                    public void run() {
                        toggleDevWarn();
                    }
                });
        devWarnToggle = new Ui.Toggle(this, u);
        devWarnToggle.setChecked(Chain.devWarnChoice(this));
        devWarnToggle.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                toggleDevWarn();
            }
        });
        warnRow.addView(devWarnToggle, new LinearLayout.LayoutParams(u.dp(52), u.dp(32)));
        secWarn.addView(warnRow);
        col.addView(secWarn, cardLp());

        addSection(col, "音频");
        LinearLayout sec2 = newCard();
        LinearLayout hifiRow = settingRow(-1, "全局 Hi-Fi（强制）",
                "有线耳机下让所有应用走 ES9038，绕过 vivo 白名单",
                null, Ui.TEXT, false, new Runnable() {
                    @Override
                    public void run() {
                        toggleHifi();
                    }
                });
        hifiToggle = new Ui.Toggle(this, u);
        hifiToggle.setChecked(Chain.hifiChoice(this));
        hifiToggle.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                toggleHifi();
            }
        });
        hifiRow.addView(hifiToggle, new LinearLayout.LayoutParams(u.dp(52), u.dp(32)));
        sec2.addView(hifiRow);
        sec2.addView(divider());
        gainRow601 = settingRow(-1, "跟随 1.15.1", "把输出增益切成 1.15.1 那一档",
                null, Ui.TEXT, false, new Runnable() {
                    @Override
                    public void run() {
                        hpGain("601");
                    }
                });
        gainCheck601 = u.icon(Ui.CHECK, Ui.PRIMARY, 16);
        gainRow601.addView(gainCheck601, trailingIconLp());
        sec2.addView(gainRow601);
        sec2.addView(divider());
        gainRowStock = settingRow(-1, "跟随本机", "写回 Xplay6 自己的 DT 值",
                null, Ui.TEXT, false, new Runnable() {
                    @Override
                    public void run() {
                        hpGain("stock");
                    }
                });
        gainCheckStock = u.icon(Ui.CHECK, Ui.PRIMARY, 16);
        gainRowStock.addView(gainCheckStock, trailingIconLp());
        sec2.addView(gainRowStock);
        col.addView(sec2, cardLp());
        hifiNote = u.text("全局 Hi-Fi：未开启", 12, Ui.MUTED, Ui.REG);
        hifiNote.setLineSpacing(u.dp(2), 1f);
        LinearLayout.LayoutParams hnLp = new LinearLayout.LayoutParams(-1, -2);
        hnLp.leftMargin = u.dp(4);
        hnLp.topMargin = u.dp(8);
        col.addView(hifiNote, hnLp);
        gainNote = u.text("耳机增益：未改（7 自己的 DT 值）", 12, Ui.MUTED, Ui.REG);
        gainNote.setLineSpacing(u.dp(2), 1f);
        LinearLayout.LayoutParams gnLp = new LinearLayout.LayoutParams(-1, -2);
        gnLp.leftMargin = u.dp(4);
        gnLp.topMargin = u.dp(8);
        col.addView(gainNote, gnLp);

        addSection(col, "诊断");
        LinearLayout sec3 = newCard();
        sec3.addView(settingRow(Ui.LOG, "运行日志", "提权链与守护进程的每一步",
                null, Ui.TEXT, true, new Runnable() {
                    @Override
                    public void run() {
                        openLog();
                    }
                }));
        sec3.addView(divider());
        sec3.addView(settingRow(Ui.SHIELD, "授权日志", "守护进程记录的 su 请求",
                null, Ui.TEXT, true, new Runnable() {
                    @Override
                    public void run() {
                        dumpSuLog();
                    }
                }));
        col.addView(sec3, cardLp());

        addSection(col, "关于");
        LinearLayout sec4 = newCard();
        sec4.addView(settingRow(Ui.INFO, "版本", null, "v" + versionName(), Ui.TEXT, false, null));
        sec4.addView(divider());
        sec4.addView(settingRow(-1, "运行方式", null, "内存态", Ui.TEXT, false, null));
        sec4.addView(divider());
        sec4.addView(settingRow(-1, "适用设备", null, "Xplay6 / PD1610", Ui.TEXT, false, null));
        sec4.addView(divider());
        sec4.addView(settingRow(-1, "系统版本支持", null, "1.15.1 · 7.12.15 · 8.19.16", Ui.TEXT, false, null));
        sec4.addView(divider());
        sec4.addView(settingRow(Ui.INFO, "项目源码",
                "https://github.com/AlexIllinois2/xplay6-tmproot",
                null, Ui.TEXT, true, new Runnable() {
                    @Override
                    public void run() {
                        try {
                            startActivity(new Intent(Intent.ACTION_VIEW,
                                    Uri.parse("https://github.com/AlexIllinois2/xplay6-tmproot")));
                        } catch (Exception ignored) {
                            Toast.makeText(Main.this, "没有可用的浏览器", Toast.LENGTH_SHORT).show();
                        }
                    }
                }));
        col.addView(sec4, cardLp());

        TextView support = u.text("系统版本支持列表\n"
                + "· 1.15.1（Android 6.0.1 / 内核 3.18.20）— modprobe / 用户态 helper 路线\n"
                + "· 7.12.15（Android 7.1.1 / 内核 3.18.31）— 内核内自提权路线\n"
                + "· 8.19.16（Android 8.1 / 内核 3.18.71）— CVE-2019-2215 内核写入路线\n"
                + "只认这三个固件版本；其它厂商版本或内核一律拒绝写入，不做任何尝试。",
                12, Ui.MUTED, Ui.REG);
        support.setLineSpacing(u.dp(3), 1f);
        LinearLayout.LayoutParams spLp = new LinearLayout.LayoutParams(-1, -2);
        spLp.leftMargin = u.dp(4);
        spLp.topMargin = u.dp(18);
        col.addView(support, spLp);

        TextView usage = u.text("使用说明\n"
                + "1. 首页点「提权」，看到 Root 已就绪即成功；失败可稍后再点一次\n"
                + "2. 到「应用授权」页点选要给 root 的应用，立即生效，无需保存\n"
                + "3. 被授权的应用在其终端里执行 su 拿 root（8.1 系统拦 su 这个名字，请用 sux）\n"
                + "4. i管家 放行本应用自启动后，重启会自动重新提权；否则每次开机手动点一次\n"
                + "5. 一切只存在于内存：重启或关机即回到出厂状态",
                12, Ui.MUTED, Ui.REG);
        usage.setLineSpacing(u.dp(3), 1f);
        LinearLayout.LayoutParams usLp = new LinearLayout.LayoutParams(-1, -2);
        usLp.leftMargin = u.dp(4);
        usLp.topMargin = u.dp(14);
        col.addView(usage, usLp);

        TextView footer = u.text("提权只改写运行内存与 SELinux 运行表，不刷机、不写任何分区、不解 BL。\n重启后所有改动自动消失，需要重新提权。",
                12, Ui.MUTED, Ui.REG);
        footer.setLineSpacing(u.dp(3), 1f);
        LinearLayout.LayoutParams ftLp = new LinearLayout.LayoutParams(-1, -2);
        ftLp.leftMargin = u.dp(4);
        ftLp.topMargin = u.dp(18);
        col.addView(footer, ftLp);
        return sv;
    }

    private void addSection(LinearLayout col, String name) {
        TextView t = u.section(name);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2);
        lp.leftMargin = u.dp(4);
        lp.topMargin = u.dp(col.getChildCount() == 0 ? 20 : 22);
        lp.bottomMargin = u.dp(8);
        col.addView(t, lp);
    }

    private LinearLayout newCard() {
        LinearLayout c = new LinearLayout(this);
        c.setOrientation(LinearLayout.VERTICAL);
        c.setBackground(u.shape(Ui.SURFACE, 20));
        c.setClipToOutline(true);
        return c;
    }

    private LinearLayout.LayoutParams cardLp() {
        return new LinearLayout.LayoutParams(-1, -2);
    }

    private View divider() {
        View v = new View(this);
        v.setBackgroundColor(0xFF26242C);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, u.dp(1));
        lp.leftMargin = u.dp(16);
        lp.rightMargin = u.dp(16);
        v.setLayoutParams(lp);
        return v;
    }

    private LinearLayout.LayoutParams trailingIconLp() {
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(u.dp(16), u.dp(16));
        lp.leftMargin = u.dp(10);
        return lp;
    }

    private LinearLayout settingRow(int glyph, String title, String sub, String value,
                                    int titleColor, boolean chevron, Runnable body) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setMinimumHeight(u.dp(64));
        row.setPadding(u.dp(16), u.dp(12), u.dp(16), u.dp(12));
        if (glyph >= 0) {
            ImageView icon = u.icon(glyph, titleColor == Ui.RED ? Ui.RED : Ui.PRIMARY, 20);
            LinearLayout.LayoutParams ilp = new LinearLayout.LayoutParams(u.dp(20), u.dp(20));
            ilp.rightMargin = u.dp(14);
            row.addView(icon, ilp);
        }
        LinearLayout texts = new LinearLayout(this);
        texts.setOrientation(LinearLayout.VERTICAL);
        texts.addView(u.text(title, 15, titleColor, Ui.MED));
        if (sub != null) {
            TextView s = u.text(sub, 12, Ui.MUTED, Ui.REG);
            LinearLayout.LayoutParams slp = new LinearLayout.LayoutParams(-1, -2);
            slp.topMargin = u.dp(2);
            texts.addView(s, slp);
        }
        row.addView(texts, new LinearLayout.LayoutParams(0, -2, 1f));
        if (value != null) {
            TextView v = u.text(value, 13, Ui.MUTED, Ui.REG);
            LinearLayout.LayoutParams vlp = new LinearLayout.LayoutParams(-2, -2);
            vlp.leftMargin = u.dp(8);
            row.addView(v, vlp);
        }
        if (chevron) {
            ImageView c = u.icon(Ui.CHEVRON, Ui.MUTED, 16);
            LinearLayout.LayoutParams clp = new LinearLayout.LayoutParams(u.dp(16), u.dp(16));
            clp.leftMargin = u.dp(8);
            row.addView(c, clp);
        }
        if (body != null) {
            row.setBackground(u.press(u.shape(0x00000000, 0)));
            row.setClickable(true);
            row.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    body.run();
                }
            });
        }
        return row;
    }

    /** Store the decision and, when it is turned on while root is already up, apply it at once.
     *  Chain.run applies it again on every successful escalation (manual 提权 and boot alike). */
    private void toggleAdbInput() {
        final boolean on = !Chain.adbInputChoice(this);
        final boolean kept = Chain.saveAdbInputChoice(this, on);
        if (adbInputToggle != null)
            adbInputToggle.setChecked(Chain.adbInputChoice(this));
        logger.line("USB模拟点击: 开关 -> " + (on ? "开" : "关") + (kept ? "" : "（保存失败）"));
        if (!on)
            return;
        new Thread(new Runnable() {
            @Override
            public void run() {
                final boolean ok = Chain.applyAdbInputChoice(Main.this, logger);
                ui.post(new Runnable() {
                    @Override
                    public void run() {
                        toast(ok ? "USB模拟点击已开启（免 vivo 账号）"
                                : "开关已存下，但这次没写成功；提权成功后会再试，详见运行日志");
                    }
                });
            }
        }).start();
    }

    /** ADB root 权限：开 = 把 uid 2000 写进授权名单；关 = 摘掉。两个守护进程都是每请求
     *  重读名单（sud.c uid_allowed / relayd.c allowed），所以立即生效，不需要重启任何进程。
     *  开关状态从名单现读（Chain.shellGranted），与「应用授权」页里 com.android.shell 那一行
     *  永远是同一枚 uid 的两种看法，不可能对不一致。 */
    private void toggleAdbRoot() {
        toggleAdbRoot(!Chain.shellGranted(this));
    }

    private void toggleAdbRoot(final boolean on) {
        new Thread(new Runnable() {
            @Override
            public void run() {
                final boolean ok = Chain.setShellGrant(Main.this, on);
                ui.post(new Runnable() {
                    @Override
                    public void run() {
                        boolean now = Chain.shellGranted(Main.this);
                        if (adbRootToggle != null)
                            adbRootToggle.setChecked(now);
                        logger.line("ADB root: uid 2000 -> " + (on ? "granted" : "revoked")
                                + " saved=" + ok + " state=" + now
                                + "  文件=" + Chain.grantsFile(Main.this).getAbsolutePath()
                                + (ok ? "" : "  why=" + Chain.lastGrantsError));
                        toast(ok
                                ? (on ? "已授权 adb shell：电脑上 su 即得 root（8.1 用 sux）"
                                      : "已撤销 adb shell 的 root 权限")
                                : "保存授权名单失败，详见运行日志");
                        /* 应用列表那一行与这个开关是同一枚 uid：改写之后必须重读，否则它还在
                         * 显示旧状态，下一次在列表里勾任何应用都会把这里的决定覆写回去。 */
                        refresh();
                    }
                });
            }
        }).start();
    }

    /** 每次设置页可见/名单被别处改过之后，让开关说真话。 */
    private void updateAdbRootSetting() {
        if (adbRootToggle == null)
            return;
        adbRootToggle.setChecked(Chain.shellGranted(this));
    }

    /** 隐藏「开发模式」黄条：开 = root 侧常驻 watcher 每 3s 取消 id=10100；关 = 删哨兵让它
     *  自己退出。开发者选项本身不动，所以 USB 调试不受影响。 */
    private void toggleDevWarn() {
        final boolean on = !Chain.devWarnChoice(this);
        final boolean kept = Chain.saveDevWarnChoice(this, on);
        if (devWarnToggle != null)
            devWarnToggle.setChecked(Chain.devWarnChoice(this));
        logger.line("开发模式警告: 开关 -> " + (on ? "开" : "关") + (kept ? "" : "（保存失败）"));
        new Thread(new Runnable() {
            @Override
            public void run() {
                final boolean ok = Chain.applyDevWarnChoice(Main.this, logger);
                ui.post(new Runnable() {
                    @Override
                    public void run() {
                        toast(on
                                ? (ok ? "已开始隐藏开发模式警告（3 秒内清除）"
                                      : "开关已存下，提权成功后会再试，详见运行日志")
                                : "已停止隐藏；系统下次提示时警告会回来");
                    }
                });
            }
        }).start();
    }

    private void updateGainSettings() {
        if (gainCheck601 == null)
            return;
        String arm = Chain.gainChoice(this);
        boolean a = "601".equals(arm);
        boolean b = "stock".equals(arm);
        gainCheck601.setVisibility(a ? View.VISIBLE : View.INVISIBLE);
        gainCheckStock.setVisibility(b ? View.VISIBLE : View.INVISIBLE);
        gainRow601.setBackground(u.press(u.shape(a ? 0x1FD3BCFD : 0x00000000, 0)));
        gainRowStock.setBackground(u.press(u.shape(b ? 0x1FD3BCFD : 0x00000000, 0)));
        gainNote.setText(a ? "耳机增益：请求 1.15.1 那档（RAM 读不回是设计如此），重启后由开机链再写"
                : b ? "耳机增益：请求本机 DT 那档"
                : "耳机增益：未改（7 自己的 DT 值）");
    }

    private void updateHifiSettings() {
        if (hifiToggle == null)
            return;
        boolean on = Chain.hifiChoice(this);
        hifiToggle.setChecked(on);
        if (hifiNote != null)
            hifiNote.setText(on
                    ? "全局 Hi-Fi：已请求 force_enable_hifi=1 · 只影响有线耳机，外放/蓝牙不变；"
                      + "重启或音频服务重启后由开机流程重放"
                    : "全局 Hi-Fi：未开启 · 关闭后本次开机内 HAL 的 force 标志可能仍粘住，重启才彻底恢复");
    }

    private void toggleHifi() {
        final boolean on = !Chain.hifiChoice(this);
        final boolean kept = Chain.saveHifiChoice(this, on);
        updateHifiSettings();
        logger.line("全局Hi-Fi: 开关 -> " + (on ? "开" : "关") + (kept ? "" : "（保存失败）"));
        new Thread(new Runnable() {
            @Override
            public void run() {
                final String out = Chain.hifiForce(on);
                final boolean ok = Chain.hifiForceLanded(out);
                logger.line("全局Hi-Fi: force_enable_hifi=" + (on ? 1 : 0) + " -> " + out);
                ui.post(new Runnable() {
                    @Override
                    public void run() {
                        toast(on
                                ? (ok ? "已请求全局 Hi-Fi，插上有线耳机后生效"
                                      : "请求没送达 AudioFlinger：" + out)
                                : "已关闭。HAL 的强制标志有粘性，重启后彻底恢复");
                    }
                });
            }
        }).start();
    }

    private void hpGain(final String arm) {
        new Thread(new Runnable() {
            @Override
            public void run() {
                String out = Chain.hpGain(Main.this, arm, logger);
                if (Chain.hpGainLanded(out)) {
                    final boolean kept = Chain.saveGainChoice(Main.this, arm);
                    logger.line("耳机增益 " + ("601".equals(arm) ? "1.15.1" : "本机") + "：已写入（RAM 读不回是设计如此）·"
                            + (kept ? "重启后开机链会再写一次" : "选择没能存下（saved=false），重启后不会自动回来")
                            + "·要暂停→播放或切一首才吃到");
                    ui.post(new Runnable() {
                        @Override
                        public void run() {
                            updateGainSettings();
                            toast(kept ? "耳机增益已写入，切换播放后生效" : "增益写入了，但选择没存下");
                        }
                    });
                } else {
                    logger.line("耳机增益 " + ("601".equals(arm) ? "1.15.1" : "本机") + "：没打到 -> "
                            + (out == null ? "null" : out));
                    toast("耳机增益没打到，详见运行日志");
                }
            }
        }).start();
    }

    private void revokeAll() {
        new Thread(new Runnable() {
            @Override
            public void run() {
                checked.clear();
                ArrayList<Integer> only = new ArrayList<Integer>();
                only.add(Integer.valueOf(android.os.Process.myUid()));
                final boolean ok = Chain.writeGrants(Main.this, only);
                logger.line("已撤销除管理端以外的全部授权 saved=" + ok);
                ui.post(new Runnable() {
                    @Override
                    public void run() {
                        refresh();
                        updateAdbRootSetting();
                        toast(ok ? "已撤销全部授权" : "撤销失败，详见运行日志");
                    }
                });
            }
        }).start();
    }

    private void probeSuName() {
        openLog();
        new Thread(new Runnable() {
            @Override
            public void run() {
                Chain.suNameProbe(Main.this, logger);
            }
        }).start();
    }

    private void dumpSuLog() {
        new Thread(new Runnable() {
            @Override
            public void run() {
                String l = Chain.suLog();
                logger.line("su log:\n" + l);
                openLog();
            }
        }).start();
    }

    /* ------------------------------------------------------------ nav/log */

    private View buildNav() {
        LinearLayout wrap = new LinearLayout(this);
        wrap.setOrientation(LinearLayout.VERTICAL);
        View line = new View(this);
        line.setBackgroundColor(0xFF232128);
        wrap.addView(line, new LinearLayout.LayoutParams(-1, u.dp(1)));

        LinearLayout bar = new LinearLayout(this);
        bar.setOrientation(LinearLayout.HORIZONTAL);
        bar.setPadding(u.dp(8), u.dp(6), u.dp(8), u.dp(6));
        int[] glyphs = navGlyphs;
        String[] labels = { "首页", "应用", "设置" };
        for (int i = 0; i < glyphs.length; i++) {
            final int idx = i;
            LinearLayout item = new LinearLayout(this);
            item.setOrientation(LinearLayout.VERTICAL);
            item.setGravity(Gravity.CENTER);
            item.setBackground(u.press(u.shape(0x00000000, 16)));
            item.setClickable(true);
            item.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    showPage(navPages[idx]);
                }
            });
            FrameLayout pill = new FrameLayout(this);
            pill.setBackground(u.shape(0x00000000, 14));
            ImageView ic = u.icon(glyphs[i], Ui.MUTED, 22);
            pill.addView(ic);
            item.addView(pill, new LinearLayout.LayoutParams(u.dp(56), u.dp(28)));
            TextView label = u.text(labels[i], 11, Ui.MUTED, Ui.REG);
            LinearLayout.LayoutParams llp = new LinearLayout.LayoutParams(-2, -2);
            llp.topMargin = u.dp(2);
            item.addView(label, llp);
            navItems[i] = item;
            navPills[i] = pill;
            navIcons[i] = ic;
            navLabels[i] = label;
            navGlyphs[i] = glyphs[i];
            bar.addView(item, new LinearLayout.LayoutParams(0, u.dp(52), 1f));
        }
        wrap.addView(bar);
        return wrap;
    }

    private void styleNav() {
        for (int i = 0; i < navGlyphs.length; i++) {
            boolean on = navPages[i] == page;
            navPills[i].setBackground(u.shape(on ? 0x26D3BCFD : 0x00000000, 14));
            navIcons[i].setImageDrawable(u.glyph(navGlyphs[i], on ? Ui.PRIMARY : Ui.MUTED));
            navLabels[i].setTextColor(on ? Ui.PRIMARY : Ui.MUTED);
            navLabels[i].setTypeface(on ? Ui.MED : Ui.REG);
        }
    }

    private void showPage(int p) {
        page = p;
        for (int i = 0; i < pages.length; i++)
            pages[i].setVisibility(i == p ? View.VISIBLE : View.GONE);
        styleNav();
        if (p == PAGE_MODULES && !modsLoaded && !modsLoading)
            refreshModules();
        if (p == PAGE_APPS && !appsLoaded && !loading)
            refresh();
        if (p == PAGE_HOME)
            status();
        if (p == PAGE_SETTINGS) {
            updateGainSettings();
            updateHifiSettings();
            updateAdbRootSetting();
        }
    }

    private View buildLogOverlay() {
        logOverlay = new FrameLayout(this);
        logOverlay.setBackgroundColor(Ui.BG);
        logOverlay.setClickable(true);
        logOverlay.setVisibility(View.GONE);

        LinearLayout col = new LinearLayout(this);
        col.setOrientation(LinearLayout.VERTICAL);
        col.setPadding(u.dp(16), u.dp(12), u.dp(16), u.dp(16));

        LinearLayout head = new LinearLayout(this);
        head.setGravity(Gravity.CENTER_VERTICAL);
        FrameLayout back = new FrameLayout(this);
        back.setBackground(u.press(u.shape(0x00000000, 22)));
        back.addView(u.icon(Ui.BACK, Ui.TEXT, 22));
        back.setClickable(true);
        back.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                closeLog();
            }
        });
        head.addView(back, new LinearLayout.LayoutParams(u.dp(44), u.dp(44)));
        LinearLayout titles = new LinearLayout(this);
        titles.setOrientation(LinearLayout.VERTICAL);
        titles.addView(u.heading("运行日志", 18, Ui.TEXT));
        titles.addView(u.text("本次开机内的提权过程", 11, Ui.MUTED, Ui.REG));
        LinearLayout.LayoutParams tlp = new LinearLayout.LayoutParams(0, -2, 1f);
        tlp.leftMargin = u.dp(6);
        head.addView(titles, tlp);
        col.addView(head, new LinearLayout.LayoutParams(-1, -2));

        FrameLayout logCard = new FrameLayout(this);
        logCard.setBackground(u.shape(Ui.SURFACE, 18));
        logScroll = new ScrollView(this);
        logScroll.setFillViewport(true);
        logScroll.setPadding(u.dp(14), u.dp(12), u.dp(14), u.dp(12));
        logScroll.setClipToPadding(false);
        logBody = u.text("", 11, Ui.MUTED, Ui.MONO);
        logBody.setTextIsSelectable(true);
        logBody.setLineSpacing(u.dp(2), 1f);
        logScroll.addView(logBody, new ScrollView.LayoutParams(-1, -2));
        logCard.addView(logScroll, new FrameLayout.LayoutParams(-1, -1));
        LinearLayout.LayoutParams lclp = new LinearLayout.LayoutParams(-1, 0, 1f);
        lclp.topMargin = u.dp(14);
        col.addView(logCard, lclp);

        logOverlay.addView(col, new FrameLayout.LayoutParams(-1, -1));
        return logOverlay;
    }

    private void appendLog(String s) {
        if (logBody == null)
            return;
        logBody.append(s + "\n");
        if (logOpen)
            scrollLog();
    }

    private void scrollLog() {
        logScroll.post(new Runnable() {
            @Override
            public void run() {
                logScroll.fullScroll(ScrollView.FOCUS_DOWN);
            }
        });
    }

    private void openLog() {
        ui.post(new Runnable() {
            @Override
            public void run() {
                if (logOpen)
                    return;
                logOpen = true;
                logOverlay.setVisibility(View.VISIBLE);
                logOverlay.setAlpha(0f);
                logOverlay.animate().alpha(1f).setDuration(150).start();
                scrollLog();
            }
        });
    }

    private void closeLog() {
        if (!logOpen)
            return;
        logOpen = false;
        logOverlay.animate().alpha(0f).setDuration(120)
                .withEndAction(new Runnable() {
                    @Override
                    public void run() {
                        logOverlay.setVisibility(View.GONE);
                        logOverlay.setAlpha(1f);
                    }
                }).start();
    }

    @Override
    public void onBackPressed() {
        if (logOpen) {
            closeLog();
            return;
        }
        if (page != PAGE_HOME) {
            showPage(PAGE_HOME);
            return;
        }
        super.onBackPressed();
    }

    /* ----------------------------------------------------------- state */

    private void refresh() {
        if (loading)
            return;
        loading = true;
        new Thread(new Runnable() {
            @Override
            public void run() {
                final List<Chain.Entry> got = Chain.listApps(Main.this);
                ui.post(new Runnable() {
                    @Override
                    public void run() {
                        loading = false;
                        appsLoaded = true;
                        all.clear();
                        all.addAll(got);
                        checked.clear();
                        for (Chain.Entry e : all)
                            if (e.granted)
                                checked.add(e.pkg);
                        rebuild();
                    }
                });
            }
        }).start();
    }

    private void status() {
        new Thread(new Runnable() {
            @Override
            public void run() {
                final String got = Chain.root("id -u; getenforce 2>/dev/null; command -v su");
                ui.post(new Runnable() {
                    @Override
                    public void run() {
                        applyStatus(got);
                    }
                });
            }
        }).start();
    }

    private void applyStatus(String got) {
        String s = got == null ? "" : got.trim();
        boolean rooted = s.startsWith("0") || s.contains("uid=0");
        boolean enforcing = s.contains("Enforcing");
        boolean permissive = s.contains("Permissive");
        boolean onPath = false;
        for (String line : s.split("[\\r\\n ]+"))
            if (line.endsWith("/su"))
                onPath = true;

        int color = rooted ? Ui.GREEN : Ui.AMBER;
        heroTitle.setText(rooted ? "Root 已就绪" : "尚未提权");
        heroTitle.setTextColor(color);
        heroBadge.setBackground(u.shape(rooted ? 0x267ADF9A : 0x26F2CC7B, 24));
        heroIcon.setImageDrawable(u.glyph(Ui.SHIELD, color));

        String se = enforcing ? "Enforcing" : permissive ? "Permissive" : "未知";
        String seLong = enforcing ? "Enforcing" : permissive ? "Permissive（兜底）" : "状态未知";
        String channel = rooted && Chain.lastChannel != null && !"-".equals(Chain.lastChannel)
                ? "\n通道 " + Chain.lastChannel : "";
        heroDetail.setText("SELinux " + seLong + " · su " + (onPath ? "在 PATH" : "不在 PATH") + channel);
        statSe.setText(se);
        statSu.setText(onPath ? "在 PATH" : "不在 PATH");
    }

    private void updateHomeStats() {
        if (statGrants == null)
            return;
        statGrants.setText(appsLoaded ? String.valueOf(checked.size()) : "—");
        updateHomeGranted();
    }

    private void updateHomeGranted() {
        if (homeGrantedList == null)
            return;
        homeGrantedList.removeAllViews();
        if (!appsLoaded) {
            if (homeGrantedCount != null)
                homeGrantedCount.setText("");
            homeGrantedList.addView(u.text("正在读取…", 12, Ui.MUTED, Ui.REG));
            return;
        }
        List<Chain.Entry> granted = new ArrayList<Chain.Entry>();
        for (Chain.Entry e : all)
            if (checked.contains(e.pkg))
                granted.add(e);
        if (homeGrantedCount != null)
            homeGrantedCount.setText(granted.isEmpty() ? "" : granted.size() + " 个");
        if (granted.isEmpty()) {
            homeGrantedList.addView(u.text("暂无已授权的应用", 12, Ui.MUTED, Ui.REG));
            return;
        }
        int limit = Math.min(granted.size(), 4);
        for (int i = 0; i < limit; i++) {
            final Chain.Entry e = granted.get(i);
            LinearLayout row = new LinearLayout(this);
            row.setGravity(Gravity.CENTER_VERTICAL);
            row.setPadding(u.dp(2), u.dp(6), u.dp(2), u.dp(6));
            row.setBackground(u.press(u.shape(0x00000000, 0)));
            ImageView icon = new ImageView(this);
            icon.setScaleType(ImageView.ScaleType.FIT_CENTER);
            LinearLayout.LayoutParams ilp = new LinearLayout.LayoutParams(u.dp(28), u.dp(28));
            ilp.rightMargin = u.dp(10);
            row.addView(icon, ilp);
            try {
                icon.setImageDrawable(getPackageManager().getApplicationIcon(e.pkg));
            } catch (Throwable t) {
                icon.setImageDrawable(u.shape(Ui.SURFACE_HI, 8));
            }
            TextView name = u.text(e.label, 14, Ui.TEXT, Ui.REG);
            name.setSingleLine(true);
            name.setEllipsize(TextUtils.TruncateAt.END);
            row.addView(name, new LinearLayout.LayoutParams(0, -2, 1f));
            row.addView(u.text("uid " + e.uid, 11, Ui.MUTED, Ui.REG));
            row.setClickable(true);
            row.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    showPage(PAGE_APPS);
                }
            });
            homeGrantedList.addView(row, new LinearLayout.LayoutParams(-1, -2));
        }
        if (granted.size() > limit) {
            TextView more = u.text("还有 " + (granted.size() - limit) + " 个，在「应用」页查看",
                    12, Ui.MUTED, Ui.REG);
            LinearLayout.LayoutParams mlp = new LinearLayout.LayoutParams(-1, -2);
            mlp.topMargin = u.dp(2);
            homeGrantedList.addView(more, mlp);
        }
    }

    private void escalate() {
        if (escalating)
            return;
        escalating = true;
        escalateLabel.setText("正在提权…");
        escalateBtn.setAlpha(0.6f);
        escalateBtn.setEnabled(false);
        refreshBtn.setEnabled(false);
        escalateProgress.setVisibility(View.VISIBLE);
        logger.line("--- 开始提权 ---");
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    Chain.run(Main.this, logger, 24);
                } catch (Throwable t) {
                    logger.line("提权链抛错: " + t);
                }
                ui.post(new Runnable() {
                    @Override
                    public void run() {
                        escalating = false;
                        escalateLabel.setText("提权");
                        escalateBtn.setAlpha(1f);
                        escalateBtn.setEnabled(true);
                        refreshBtn.setEnabled(true);
                        escalateProgress.setVisibility(View.GONE);
                        status();
                        refresh();
                        toast("提权流程结束，状态已刷新");
                    }
                });
            }
        }).start();
    }

    private String versionName() {
        try {
            return getPackageManager().getPackageInfo(getPackageName(), 0).versionName;
        } catch (Throwable t) {
            return "未知版本";
        }
    }

    private void toast(final String s) {
        ui.post(new Runnable() {
            @Override
            public void run() {
                Toast.makeText(Main.this, s, Toast.LENGTH_SHORT).show();
            }
        });
    }
}
