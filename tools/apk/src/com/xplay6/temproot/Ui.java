package com.xplay6.temproot;

import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.PixelFormat;
import android.graphics.Rect;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.RippleDrawable;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;

/** Drawing primitives for the Material-3-style shell.  The APK is built with aapt
 *  alone (no AndroidX, no resource compiler for vector XML), so every shape and
 *  glyph here is drawn on a Canvas rather than inflated. */
final class Ui {

    static final int BG = 0xFF101014;
    static final int SURFACE = 0xFF1A191F;
    static final int SURFACE_HI = 0xFF24222A;
    static final int OUTLINE = 0xFF34313C;
    static final int TEXT = 0xFFE9E4EC;
    static final int MUTED = 0xFFA29BA8;
    static final int PRIMARY = 0xFFD3BCFD;
    static final int ON_PRIMARY = 0xFF2A1150;
    static final int GREEN = 0xFF7ADF9A;
    static final int AMBER = 0xFFF2CC7B;
    static final int RED = 0xFFFFB4AB;
    static final int RIPPLE = 0x33FFFFFF;

    static final Typeface REG = Typeface.create("sans-serif", Typeface.NORMAL);
    static final Typeface MED = Typeface.create("sans-serif-medium", Typeface.NORMAL);
    static final Typeface BOLD = Typeface.create("sans-serif", Typeface.BOLD);
    static final Typeface MONO = Typeface.MONOSPACE;

    /* Glyph kinds. */
    static final int HOME = 0, APPS = 1, SETTINGS = 2, SHIELD = 3, CHEVRON = 4,
            BACK = 5, LOG = 6, TRASH = 7, TERMINAL = 8, AUDIO = 9, INFO = 10,
            SEARCH = 11, CHECK = 12;

    private final Context ctx;
    private final float density;

    Ui(Context c) {
        ctx = c;
        density = c.getResources().getDisplayMetrics().density;
    }

    int dp(float v) {
        return (int) (v * density + 0.5f);
    }

    TextView text(String s, float sp, int color, Typeface tf) {
        TextView t = new TextView(ctx);
        t.setText(s);
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, sp);
        t.setTextColor(color);
        t.setTypeface(tf);
        return t;
    }

    TextView heading(String s, float sp, int color) {
        TextView t = text(s, sp, color, MED);
        t.setIncludeFontPadding(false);
        t.setLetterSpacing(-0.01f);
        return t;
    }

    TextView section(String s) {
        TextView t = text(s, 12, PRIMARY, MED);
        t.setLetterSpacing(0.08f);
        return t;
    }

    GradientDrawable shape(int color, float radiusDp) {
        GradientDrawable g = new GradientDrawable();
        g.setCornerRadius(dp(radiusDp));
        g.setColor(color);
        return g;
    }

    GradientDrawable shape(int color, float radiusDp, int strokeDp, int strokeColor) {
        GradientDrawable g = shape(color, radiusDp);
        if (strokeDp > 0)
            g.setStroke(dp(strokeDp), strokeColor);
        return g;
    }

    /** A card row whose top and/or bottom corners follow the group. */
    GradientDrawable groupBg(float topDp, float bottomDp) {
        GradientDrawable g = new GradientDrawable();
        float t = dp(topDp), b = dp(bottomDp);
        g.setCornerRadii(new float[] { t, t, t, t, b, b, b, b });
        g.setColor(SURFACE);
        return g;
    }

    Drawable press(Drawable content) {
        return new RippleDrawable(ColorStateList.valueOf(RIPPLE), content, null);
    }

    Drawable press(int color, float radiusDp) {
        return press(shape(color, radiusDp));
    }

    Drawable glyph(int kind, int color) {
        return new Glyph(kind, color);
    }

    ImageView icon(int kind, int color, int sizeDp) {
        ImageView v = new ImageView(ctx);
        v.setImageDrawable(glyph(kind, color));
        v.setScaleType(ImageView.ScaleType.FIT_CENTER);
        v.setLayoutParams(new FrameLayout.LayoutParams(dp(sizeDp), dp(sizeDp), Gravity.CENTER));
        return v;
    }

    private static final class Glyph extends Drawable {
        private final int kind, color;
        private final Paint stroke = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final Paint fill = new Paint(Paint.ANTI_ALIAS_FLAG);

        Glyph(int kind, int color) {
            this.kind = kind;
            this.color = color;
            stroke.setStyle(Paint.Style.STROKE);
            stroke.setStrokeCap(Paint.Cap.ROUND);
            stroke.setStrokeJoin(Paint.Join.ROUND);
            stroke.setStrokeWidth(1.8f);
            stroke.setColor(color);
            fill.setStyle(Paint.Style.FILL);
            fill.setColor(color);
        }

        @Override
        public void draw(Canvas c) {
            Rect b = getBounds();
            if (b.width() <= 0 || b.height() <= 0)
                return;
            float s = Math.min(b.width(), b.height()) / 24f;
            c.save();
            c.translate(b.left + (b.width() - 24f * s) / 2f, b.top + (b.height() - 24f * s) / 2f);
            c.scale(s, s);
            Path p = new Path();
            switch (kind) {
                case HOME:
                    p.moveTo(3.6f, 10.6f);
                    p.lineTo(12f, 3.6f);
                    p.lineTo(20.4f, 10.6f);
                    c.drawPath(p, stroke);
                    p.reset();
                    p.moveTo(5.4f, 9.4f);
                    p.lineTo(5.4f, 20.3f);
                    p.lineTo(9.7f, 20.3f);
                    p.lineTo(9.7f, 14.2f);
                    p.lineTo(14.3f, 14.2f);
                    p.lineTo(14.3f, 20.3f);
                    p.lineTo(18.6f, 20.3f);
                    p.lineTo(18.6f, 9.4f);
                    c.drawPath(p, stroke);
                    break;
                case APPS:
                    c.drawRoundRect(3.6f, 3.6f, 10.8f, 10.8f, 2.2f, 2.2f, fill);
                    c.drawRoundRect(13.2f, 3.6f, 20.4f, 10.8f, 2.2f, 2.2f, fill);
                    c.drawRoundRect(3.6f, 13.2f, 10.8f, 20.4f, 2.2f, 2.2f, fill);
                    c.drawRoundRect(13.2f, 13.2f, 20.4f, 20.4f, 2.2f, 2.2f, fill);
                    break;
                case SETTINGS:
                    c.drawLine(3.8f, 7f, 20.2f, 7f, stroke);
                    c.drawLine(3.8f, 12f, 20.2f, 12f, stroke);
                    c.drawLine(3.8f, 17f, 20.2f, 17f, stroke);
                    c.drawCircle(9f, 7f, 2.3f, fill);
                    c.drawCircle(15.2f, 12f, 2.3f, fill);
                    c.drawCircle(7.4f, 17f, 2.3f, fill);
                    break;
                case SHIELD:
                    p.moveTo(12f, 3.4f);
                    p.lineTo(19.8f, 6.2f);
                    p.lineTo(19.8f, 11.6f);
                    p.cubicTo(19.8f, 16.4f, 16.4f, 19.7f, 12f, 21f);
                    p.cubicTo(7.6f, 19.7f, 4.2f, 16.4f, 4.2f, 11.6f);
                    p.lineTo(4.2f, 6.2f);
                    p.close();
                    c.drawPath(p, stroke);
                    p.reset();
                    p.moveTo(8.4f, 12f);
                    p.lineTo(11f, 14.6f);
                    p.lineTo(15.8f, 9.4f);
                    c.drawPath(p, stroke);
                    break;
                case CHEVRON:
                    p.moveTo(9.4f, 6f);
                    p.lineTo(15.4f, 12f);
                    p.lineTo(9.4f, 18f);
                    c.drawPath(p, stroke);
                    break;
                case BACK:
                    p.moveTo(14.6f, 5.4f);
                    p.lineTo(8f, 12f);
                    p.lineTo(14.6f, 18.6f);
                    c.drawPath(p, stroke);
                    break;
                case LOG:
                    p.moveTo(6.4f, 3.4f);
                    p.lineTo(13.8f, 3.4f);
                    p.lineTo(17.6f, 7.2f);
                    p.lineTo(17.6f, 20.6f);
                    p.lineTo(6.4f, 20.6f);
                    p.close();
                    c.drawPath(p, stroke);
                    p.reset();
                    p.moveTo(13.8f, 3.4f);
                    p.lineTo(13.8f, 7.2f);
                    p.lineTo(17.6f, 7.2f);
                    c.drawPath(p, stroke);
                    c.drawLine(9.2f, 11.4f, 14.8f, 11.4f, stroke);
                    c.drawLine(9.2f, 14.6f, 14.8f, 14.6f, stroke);
                    c.drawLine(9.2f, 17.8f, 12.8f, 17.8f, stroke);
                    break;
                case TRASH:
                    c.drawLine(4.6f, 7f, 19.4f, 7f, stroke);
                    p.moveTo(9.6f, 7f);
                    p.lineTo(9.6f, 4.6f);
                    p.lineTo(14.4f, 4.6f);
                    p.lineTo(14.4f, 7f);
                    c.drawPath(p, stroke);
                    p.reset();
                    p.moveTo(6.6f, 7f);
                    p.lineTo(7.6f, 20.4f);
                    p.lineTo(16.4f, 20.4f);
                    p.lineTo(17.4f, 7f);
                    c.drawPath(p, stroke);
                    c.drawLine(10.4f, 10.2f, 10.7f, 17.2f, stroke);
                    c.drawLine(13.6f, 10.2f, 13.3f, 17.2f, stroke);
                    break;
                case TERMINAL:
                    c.drawRoundRect(3.4f, 4.4f, 20.6f, 19.6f, 2.6f, 2.6f, stroke);
                    p.moveTo(7.6f, 9.5f);
                    p.lineTo(10.6f, 12f);
                    p.lineTo(7.6f, 14.5f);
                    c.drawPath(p, stroke);
                    c.drawLine(12.6f, 14.5f, 16.8f, 14.5f, stroke);
                    break;
                case AUDIO:
                    p.moveTo(4.6f, 14.4f);
                    p.lineTo(4.6f, 12f);
                    p.cubicTo(4.6f, 7.9f, 8f, 4.6f, 12f, 4.6f);
                    p.cubicTo(16f, 4.6f, 19.4f, 7.9f, 19.4f, 12f);
                    p.lineTo(19.4f, 14.4f);
                    c.drawPath(p, stroke);
                    c.drawRoundRect(3.4f, 13.4f, 7.4f, 19.2f, 1.8f, 1.8f, fill);
                    c.drawRoundRect(16.6f, 13.4f, 20.6f, 19.2f, 1.8f, 1.8f, fill);
                    break;
                case INFO:
                    c.drawCircle(12f, 12f, 8.5f, stroke);
                    c.drawCircle(12f, 8f, 1.1f, fill);
                    c.drawLine(12f, 11f, 12f, 16.4f, stroke);
                    break;
                case SEARCH:
                    c.drawCircle(10.6f, 10.6f, 6.1f, stroke);
                    c.drawLine(15.1f, 15.1f, 20.2f, 20.2f, stroke);
                    break;
                case CHECK:
                    p.moveTo(5.2f, 12.4f);
                    p.lineTo(10f, 17.2f);
                    p.lineTo(18.8f, 7.4f);
                    c.drawPath(p, stroke);
                    break;
                default:
                    break;
            }
            c.restore();
        }

        @Override
        public void setAlpha(int alpha) {
            stroke.setAlpha(alpha);
            fill.setAlpha(alpha);
        }

        @Override
        public void setColorFilter(ColorFilter cf) {
            stroke.setColorFilter(cf);
            fill.setColorFilter(cf);
        }

        @Override
        public int getOpacity() {
            return PixelFormat.TRANSLUCENT;
        }
    }

    /** The M3-style switch: 52x32 track, travelling thumb. */
    static final class Toggle extends FrameLayout {
        private final View thumb;
        private final GradientDrawable track, thumbBg;
        private boolean on;

        Toggle(Context c, Ui u) {
            super(c);
            track = new GradientDrawable();
            track.setCornerRadius(u.dp(16));
            track.setStroke(u.dp(2), OUTLINE);
            track.setColor(0x00000000);
            setBackground(track);
            thumb = new View(c);
            thumbBg = new GradientDrawable();
            thumbBg.setShape(GradientDrawable.OVAL);
            thumb.setBackground(thumbBg);
            addView(thumb, new FrameLayout.LayoutParams(u.dp(20), u.dp(20)));
            setOnClickListener(new OnClickListener() {
                @Override
                public void onClick(View v) {
                    setChecked(!on);
                }
            });
            apply(false);
        }

        void setChecked(boolean v) {
            if (on == v)
                return;
            on = v;
            apply(true);
        }

        boolean isChecked() {
            return on;
        }

        private void apply(boolean animate) {
            int size = dpForThumb(on ? 24 : 20);
            FrameLayout.LayoutParams lp = (FrameLayout.LayoutParams) thumb.getLayoutParams();
            lp.width = size;
            lp.height = size;
            lp.gravity = Gravity.CENTER_VERTICAL | (on ? Gravity.END : Gravity.START);
            lp.leftMargin = dpForThumb(on ? 4 : 6);
            lp.rightMargin = dpForThumb(on ? 4 : 6);
            thumb.setLayoutParams(lp);
            track.setColor(on ? PRIMARY : 0x00000000);
            track.setStroke(dpForThumb(2), on ? PRIMARY : OUTLINE);
            thumbBg.setColor(on ? ON_PRIMARY : MUTED);
            if (animate)
                thumb.animate().scaleX(1f).scaleY(1f).setDuration(120).start();
        }

        private final float d = getResources().getDisplayMetrics().density;

        private int dpForThumb(float v) {
            return (int) (v * d + 0.5f);
        }
    }
}
