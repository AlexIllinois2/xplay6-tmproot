package com.xplay6.temproot;

import android.app.Activity;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/* One screen: a status card, the Su allow list, and a collapsible log.
 *
 * The list is the whole point of the design: it shows every installable application
 * with the uid the daemon will attribute to it, and the pills decide the allow
 * list.  Nothing here creates a `su` for anyone -- an app that is off has no channel
 * to find, so "被拒绝" and "不存在" look identical from the outside.
 *
 * Look is Material 3 dark: the KernelSU reference APK is Compose-only and minSdk 31,
 * so it cannot be run on this API 23 device to be sampled.  Colours are the spec's
 * own dark baseline roles, metrics are its layout's (16dp page, 64dp rows, 40dp
 * icons, 52x32 pill with a 24dp thumb, 15sp title / 12sp supporting).
 */
public final class Main extends Activity {

    static final int C_BG = 0xFF1C1B1F;
    static final int C_CARD = 0xFF2B2930;
    static final int C_CARD_HI = 0xFF36343B;
    static final int C_TEXT = 0xFFE6E1E5;
    static final int C_MUTED = 0xFFCAC4D0;
    static final int C_OUTLINE = 0xFF938F99;
    static final int C_PRIMARY = 0xFFD0BCFF;
    static final int C_ON_PRIMARY = 0xFF381E72;
    static final int C_DIVIDER = 0x14E6E1E5;

    /* Typeface.NORMAL is an int style, not a Typeface -- text() takes the face. */
    static final Typeface TF = Typeface.create("sans-serif", Typeface.NORMAL);

    private final Handler ui = new Handler(Looper.getMainLooper());
    private final List<Chain.Entry> all = new ArrayList<Chain.Entry>();
    private final List<Chain.Entry> rows = new ArrayList<Chain.Entry>();
    private final Set<String> checked = new HashSet<String>();

    private TextView logBody, logHead, statusLine, countLine, systemChip;
    private ScrollView logScroll;
    private ListView list;
    private boolean showSystem;
    private boolean logOpen;

    private final Chain.Log logger = new Chain.Log() {
        @Override
        public void line(final String s) {
            Log.i("TempRoot", s);
            ui.post(new Runnable() {
                @Override
                public void run() {
                    logBody.append(s + "\n");
                    logScroll.post(new Runnable() {
                        @Override
                        public void run() {
                            logScroll.fullScroll(ScrollView.FOCUS_DOWN);
                        }
                    });
                }
            });
        }
    };

    /* Section titles ride in the same list as the apps, smuggled in as an Entry with
     * no package name -- and disabled, so tapping one cannot toggle anything. */
    private final BaseAdapter adapter = new BaseAdapter() {
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
        public int getViewTypeCount() {
            return 2;
        }

        @Override
        public int getItemViewType(int pos) {
            return isHeader(rows.get(pos)) ? 0 : 1;
        }

        @Override
        public boolean areAllItemsEnabled() {
            return false;
        }

        @Override
        public boolean isEnabled(int pos) {
            return !isHeader(rows.get(pos));
        }

        @Override
        public View getView(int pos, View cv, ViewGroup parent) {
            Chain.Entry e = rows.get(pos);
            return isHeader(e) ? headerRow(cv, e) : appRow(cv, e);
        }
    };

    @Override
    protected void onCreate(Bundle saved) {
        super.onCreate(saved);

        getWindow().setStatusBarColor(C_BG);
        getWindow().setNavigationBarColor(C_BG);

        LinearLayout page = new LinearLayout(this);
        page.setOrientation(LinearLayout.VERTICAL);
        page.setBackgroundColor(C_BG);
        page.setPadding(dp(16), dp(20), dp(16), dp(12));

        TextView title = text("月虹提权助手", 22, C_TEXT, Typeface.create("sans-serif", Typeface.BOLD));
        title.setLetterSpacing(-0.01f);
        page.addView(title);
        TextView sub = text("仅内存态提权 · 重启即回到出厂状态", 12, C_MUTED, TF);
        LinearLayout.LayoutParams subLp = new LinearLayout.LayoutParams(-1, -2);
        subLp.topMargin = dp(4);
        subLp.bottomMargin = dp(14);
        page.addView(sub, subLp);

        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackground(round(C_CARD, 14));
        card.setPadding(dp(16), dp(14), dp(16), dp(14));

        statusLine = text("状态读取中…", 14, C_TEXT, TF);
        card.addView(statusLine);
        countLine = text("", 12, C_MUTED, TF);
        LinearLayout.LayoutParams cntLp = new LinearLayout.LayoutParams(-1, -2);
        cntLp.topMargin = dp(3);
        card.addView(countLine, cntLp);

        LinearLayout actions = new LinearLayout(this);
        actions.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams actLp = new LinearLayout.LayoutParams(-1, -2);
        actLp.topMargin = dp(12);
        actions.addView(chip("提权", new Runnable() {
            @Override
            public void run() {
                openLog();
                logger.line("--- escalate ---");
                Chain.run(Main.this, logger, 24);
                status();
            }
        }));
        actions.addView(chip("刷新", new Runnable() {
            @Override
            public void run() {
                refresh();
                status();
            }
        }));
        systemChip = chip("系统应用：隐藏", null);
        systemChip.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                showSystem = !showSystem;
                styleSystemChip();
                ui.post(new Runnable() {
                    @Override
                    public void run() {
                        rebuild();
                    }
                });
            }
        });
        actions.addView(systemChip);
        card.addView(actions, actLp);
        page.addView(card);

        list = new ListView(this);
        list.setAdapter(adapter);
        list.setBackgroundColor(Color.TRANSPARENT);
        list.setDivider(new ColorDrawable(C_DIVIDER));
        list.setDividerHeight(1);
        list.setSelector(new ColorDrawable(Color.TRANSPARENT));
        list.setCacheColorHint(Color.TRANSPARENT);
        list.setFadingEdgeLength(0);
        /* The classic scrollbar thumb lands on top of the pills at this density, and
         * a Compose-era list does not draw one -- so it is off, not styled. */
        list.setVerticalScrollBarEnabled(false);
        list.setClipToPadding(false);
        list.setPadding(0, dp(4), 0, dp(10));
        page.addView(list, new LinearLayout.LayoutParams(-1, 0, 1f));

        LinearLayout tools = new LinearLayout(this);
        tools.setOrientation(LinearLayout.HORIZONTAL);
        tools.addView(chip("测 su 名字闸", new Runnable() {
            @Override
            public void run() {
                openLog();
                Chain.suNameProbe(Main.this, logger);
            }
        }));
        tools.addView(chip("撤销全部", new Runnable() {
            @Override
            public void run() {
                openLog();
                checked.clear();
                ArrayList<Integer> only = new ArrayList<Integer>();
                only.add(Integer.valueOf(android.os.Process.myUid()));
                boolean ok = Chain.writeGrants(Main.this, only);
                logger.line("已撤销除管理端以外的全部授权 saved=" + ok);
                refresh();
            }
        }));
        tools.addView(chip("授权日志", new Runnable() {
            @Override
            public void run() {
                openLog();
                logger.line("su log:\n" + Chain.suLog());
            }
        }));
        LinearLayout.LayoutParams toolsLp = new LinearLayout.LayoutParams(-1, -2);
        toolsLp.topMargin = dp(10);
        page.addView(tools, toolsLp);

        logHead = text("运行日志      点按展开", 12, C_PRIMARY, TF);
        logHead.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                setLogOpen(!logOpen);
            }
        });
        LinearLayout.LayoutParams headLp = new LinearLayout.LayoutParams(-1, -2);
        headLp.topMargin = dp(12);
        headLp.bottomMargin = dp(6);
        page.addView(logHead, headLp);

        logBody = text("", 11, C_MUTED, Typeface.MONOSPACE);
        logBody.setTextIsSelectable(true);
        logScroll = new ScrollView(this);
        logScroll.setBackground(round(C_CARD, 14));
        logScroll.addView(logBody);
        logScroll.setVisibility(View.GONE);
        page.addView(logScroll, new LinearLayout.LayoutParams(-1, dp(120)));

        setContentView(page);

        styleSystemChip();
        Chain.useToken(this);
        /* Read it from the package, never from a literal: the log line used to say
         * "1.4" while the manifest had moved on, which is the kind of lie that makes a
         * later reader distrust every other line in this log. */
        String ver;
        try {
            ver = getPackageManager().getPackageInfo(getPackageName(), 0).versionName;
        } catch (Throwable t) {
            ver = "未知版本";
        }
        logger.line("月虹提权助手 " + ver + " · 仅内存态：重启回到出厂；未提权时任何 PATH 上都没有 su");
        refresh();
        status();
    }

    /* The buttons and rows run their body on a worker thread (the chain blocks for
     * tens of seconds), so the query happens there and only the view update is posted
     * back to the UI thread -- calling notifyDataSetChanged() from the worker threw
     * CalledFromWrongThreadException and took the app down. */
    private void refresh() {
        new Thread(new Runnable() {
            @Override
            public void run() {
                final List<Chain.Entry> got = Chain.listApps(Main.this);
                ui.post(new Runnable() {
                    @Override
                    public void run() {
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

    private void rebuild() {
        List<Chain.Entry> on = new ArrayList<Chain.Entry>();
        List<Chain.Entry> other = new ArrayList<Chain.Entry>();
        List<Chain.Entry> sys = new ArrayList<Chain.Entry>();
        int hidden = 0;

        for (Chain.Entry e : all) {
            if (e.system) {
                if (!showSystem) {
                    hidden++;
                    continue;
                }
                sys.add(e);
            } else if (checked.contains(e.pkg)) {
                on.add(e);
            } else {
                other.add(e);
            }
        }
        /* A granted system app has to stay visible even while 系统应用 is hidden, or
         * the allow list would hold entries the screen claims do not exist. */
        for (Chain.Entry e : sys)
            if (checked.contains(e.pkg) && !on.contains(e))
                on.add(e);

        rows.clear();
        if (!on.isEmpty()) {
            rows.add(header("已授权  " + on.size()));
            rows.addAll(on);
        }
        if (!other.isEmpty()) {
            rows.add(header("可授权的应用  " + other.size()));
            rows.addAll(other);
        }
        if (!sys.isEmpty()) {
            rows.add(header("系统应用  " + sys.size()));
            rows.addAll(sys);
        }
        countLine.setText("已授权 " + on.size() + " 项 · 列表 " + (on.size() + other.size() + sys.size())
                + " 项 · 已隐藏 " + hidden + " 个系统应用");
        adapter.notifyDataSetChanged();
    }

    private void toggle(final Chain.Entry e) {
        if (e.uid == android.os.Process.myUid()) {
            toast("本应用始终保持授权，否则没人能再改这张表");
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
                /* KernelSU has no save button: flipping a row *is* the decision, so the
                 * list goes to disk here rather than sitting staged on screen. */
                final boolean ok = Chain.saveSelection(Main.this, all, new ArrayList<String>(checked));
                final String now = Chain.root("id");
                ui.post(new Runnable() {
                    @Override
                    public void run() {
                        logger.line((on ? "已授权 " : "已撤销 ") + e.pkg + "  uid=" + e.uid
                                + "  saved=" + ok + "  文件=" + Chain.grantsFile(Main.this).getAbsolutePath());
                        logger.line("守护进程现在对我说的身份: " + now);
                        if (ok)
                            status();
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
        StringBuilder b = new StringBuilder();
        b.append(rooted ? "root 可用" : "尚未提权 · 点「提权」跑一次链子");
        if (s.contains("Enforcing"))
            b.append(" · Enforcing（按域）");
        else if (s.contains("Permissive"))
            b.append(" · Permissive（兜底）");
        boolean onPath = false;
        for (String line : s.split("[\\r\\n ]+"))
            if (line.endsWith("/su"))
                onPath = true;
        b.append(" · su ").append(onPath ? "在 PATH" : "不在 PATH");
        statusLine.setText(b);
    }

    private static boolean isHeader(Chain.Entry e) {
        return e.pkg == null;
    }

    private static Chain.Entry header(String label) {
        Chain.Entry e = new Chain.Entry(null, label, 0, false);
        e.granted = false;
        return e;
    }

    private View headerRow(View cv, Chain.Entry e) {
        TextView t = (cv instanceof TextView) ? (TextView) cv : new TextView(this);
        t.setText(e.label.toUpperCase());
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        t.setTextColor(C_PRIMARY);
        t.setTypeface(TF);
        t.setLetterSpacing(0.06f);
        t.setPadding(dp(14), dp(14), dp(14), dp(6));
        return t;
    }

    private static final class Holder {
        ImageView icon;
        TextView name, detail;
        FrameLayout pill;
        GradientDrawable pillBg;
        View thumb;
        GradientDrawable thumbBg;
    }

    private View appRow(View cv, final Chain.Entry e) {
        LinearLayout row;
        final Holder h;
        if (cv instanceof LinearLayout && ((LinearLayout) cv).getTag() instanceof Holder) {
            row = (LinearLayout) cv;
            h = (Holder) row.getTag();
        } else {
            row = new LinearLayout(this);
            row.setOrientation(LinearLayout.HORIZONTAL);
            row.setGravity(Gravity.CENTER_VERTICAL);
            row.setBackgroundResource(selectableItemBackground());
            h = new Holder();

            h.icon = new ImageView(this);
            h.icon.setScaleType(ImageView.ScaleType.FIT_CENTER);
            LinearLayout.LayoutParams iconLp = new LinearLayout.LayoutParams(dp(40), dp(40));
            iconLp.rightMargin = dp(14);
            row.addView(h.icon, iconLp);

            LinearLayout col = new LinearLayout(this);
            col.setOrientation(LinearLayout.VERTICAL);
            col.setLayoutParams(new LinearLayout.LayoutParams(0, -2, 1f));

            h.name = text("", 15, C_TEXT, TF);
            h.name.setSingleLine(true);
            h.name.setEllipsize(android.text.TextUtils.TruncateAt.END);
            col.addView(h.name, new LinearLayout.LayoutParams(-1, -2));

            h.detail = text("", 12, C_MUTED, TF);
            h.detail.setSingleLine(true);
            h.detail.setEllipsize(android.text.TextUtils.TruncateAt.END);
            LinearLayout.LayoutParams detLp = new LinearLayout.LayoutParams(-1, -2);
            detLp.topMargin = dp(3);
            col.addView(h.detail, detLp);
            row.addView(col);

            h.pill = new FrameLayout(this);
            h.pillBg = round(16);
            h.pill.setBackground(h.pillBg);
            h.pill.setClickable(false);
            row.addView(h.pill, new LinearLayout.LayoutParams(dp(52), dp(32)));

            h.thumb = new View(this);
            h.thumbBg = new GradientDrawable();
            h.thumbBg.setShape(GradientDrawable.OVAL);
            h.thumb.setBackground(h.thumbBg);
            row.setTag(h);
        }

        boolean on = checked.contains(e.pkg);
        h.name.setText(e.uid == android.os.Process.myUid() ? e.label + "（本应用）" : e.label);
        h.detail.setText("uid " + e.uid + "   ·   " + e.pkg);
        try {
            h.icon.setImageDrawable(getPackageManager().getApplicationIcon(e.pkg));
        } catch (Throwable t) {
            h.icon.setImageDrawable(round(C_CARD_HI, 12));
        }

        h.pillBg.setColor(on ? C_PRIMARY : Color.TRANSPARENT);
        h.pillBg.setStroke(dp(2), on ? C_PRIMARY : C_OUTLINE);
        h.thumbBg.setColor(on ? C_ON_PRIMARY : C_MUTED);
        h.thumb.setAlpha(on ? 1f : 0.75f);
        FrameLayout.LayoutParams thumbLp = new FrameLayout.LayoutParams(dp(on ? 24 : 20), dp(on ? 24 : 20));
        thumbLp.gravity = Gravity.CENTER_VERTICAL | (on ? Gravity.END : Gravity.START);
        thumbLp.rightMargin = dp(on ? 4 : 6);
        thumbLp.leftMargin = dp(on ? 0 : 6);
        h.thumb.setLayoutParams(thumbLp);
        if (h.thumb.getParent() == null)
            h.pill.addView(h.thumb);

        row.setMinimumHeight(dp(64));
        row.setPadding(dp(14), dp(10), dp(14), dp(10));
        row.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                toggle(e);
            }
        });
        return row;
    }

    private void styleSystemChip() {
        systemChip.setText(showSystem ? "系统应用：显示中" : "系统应用：隐藏");
        systemChip.setBackground(chipDrawable(showSystem));
    }

    private void setLogOpen(boolean open) {
        logOpen = open;
        logScroll.setVisibility(open ? View.VISIBLE : View.GONE);
        logHead.setText(open ? "运行日志      点按收起" : "运行日志      点按展开");
        if (open)
            logScroll.post(new Runnable() {
                @Override
                public void run() {
                    logScroll.fullScroll(ScrollView.FOCUS_DOWN);
                }
            });
    }

    /* The chip bodies run on a worker, so opening the log has to be posted. */
    private void openLog() {
        ui.post(new Runnable() {
            @Override
            public void run() {
                setLogOpen(true);
            }
        });
    }

    private TextView chip(String label, Runnable body) {
        TextView t = text(label, 12, C_PRIMARY, TF);
        t.setGravity(Gravity.CENTER);
        t.setMinWidth(dp(64));
        int px = dp(14);
        t.setPadding(px, 0, px, 0);
        t.setBackground(chipDrawable(false));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-2, dp(32));
        lp.rightMargin = dp(8);
        t.setLayoutParams(lp);
        if (body != null)
            t.setOnClickListener(new ThreadClick(body));
        return t;
    }

    /* Chip bodies touch the daemon and the kernel chain, which blocks for tens of
     * seconds -- a tap must never freeze the list. */
    private final class ThreadClick implements View.OnClickListener {
        private final Runnable body;

        ThreadClick(Runnable body) {
            this.body = body;
        }

        @Override
        public void onClick(View v) {
            new Thread(body).start();
        }
    }

    private GradientDrawable chipDrawable(boolean selected) {
        GradientDrawable g = round(16);
        g.setColor(selected ? 0x2AD0BCFF : 0x00000000);
        g.setStroke(dp(1), selected ? C_PRIMARY : 0x40D0BCFF);
        return g;
    }

    private static GradientDrawable round(int radiusDp) {
        GradientDrawable g = new GradientDrawable();
        g.setCornerRadius(radiusDp);
        return g;
    }

    private GradientDrawable round(int color, int radiusDp) {
        GradientDrawable g = round(radiusDp);
        g.setColor(color);
        return g;
    }

    private int selectableItemBackground() {
        TypedValue v = new TypedValue();
        if (getTheme().resolveAttribute(android.R.attr.selectableItemBackground, v, true))
            return v.resourceId;
        return android.R.color.transparent;
    }

    private TextView text(String s, float sp, int color, Typeface tf) {
        TextView t = new TextView(this);
        t.setText(s);
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, sp);
        t.setTextColor(color);
        t.setTypeface(tf);
        return t;
    }

    private int dp(float v) {
        return (int) TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v,
                getResources().getDisplayMetrics());
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
