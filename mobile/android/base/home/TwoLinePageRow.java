/* -*- Mode: Java; c-basic-offset: 4; tab-width: 20; indent-tabs-mode: nil; -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.gecko.home;

import org.mozilla.gecko.favicons.Favicons;
import org.mozilla.gecko.R;
import org.mozilla.gecko.Tab;
import org.mozilla.gecko.Tabs;
import org.mozilla.gecko.db.BrowserContract.Combined;
import org.mozilla.gecko.db.BrowserDB.URLColumns;
import org.mozilla.gecko.gfx.BitmapUtils;
import org.mozilla.gecko.util.ThreadUtils;
import org.mozilla.gecko.widget.FaviconView;

import android.content.Context;
import android.database.Cursor;
import android.graphics.Bitmap;
import android.text.TextUtils;
import android.util.AttributeSet;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.widget.LinearLayout;
import android.widget.TextView;

public class TwoLinePageRow extends LinearLayout
                            implements Tabs.OnTabsChangedListener {
    private static final int NO_ICON = 0;

    private final TextView mTitle;
    private final TextView mUrl;
    private final FaviconView mFavicon;

    private int mUrlIconId;
    private int mBookmarkIconId;
    private boolean mShowIcons;

    // The URL for the page corresponding to this view.
    private String mPageUrl;

    public TwoLinePageRow(Context context) {
        this(context, null);
    }

    public TwoLinePageRow(Context context, AttributeSet attrs) {
        super(context, attrs);

        setGravity(Gravity.CENTER_VERTICAL);

        mUrlIconId = NO_ICON;
        mBookmarkIconId = NO_ICON;
        mShowIcons = true;

        LayoutInflater.from(context).inflate(R.layout.two_line_page_row, this);
        mTitle = (TextView) findViewById(R.id.title);
        mUrl = (TextView) findViewById(R.id.url);
        mFavicon = (FaviconView) findViewById(R.id.favicon);
    }

    @Override
    protected void onAttachedToWindow() {
        Tabs.registerOnTabsChangedListener(this);
    }

    @Override
    protected void onDetachedFromWindow() {
        // Delay removing the listener to avoid modifying mTabsChangedListeners
        // while notifyListeners is iterating through the array.
        ThreadUtils.postToUiThread(new Runnable() {
            @Override
            public void run() {
                Tabs.unregisterOnTabsChangedListener(TwoLinePageRow.this);
            }
        });
    }

    @Override
    public void onTabChanged(final Tab tab, final Tabs.TabEvents msg, final Object data) {
        switch(msg) {
            case ADDED:
            case CLOSED:
            case LOCATION_CHANGE:
                updateDisplayedUrl();
                break;
        }
    }

    private void setTitle(String title) {
        mTitle.setText(title);
    }

    private void setUrl(String url) {
        mUrl.setText(url);
    }

    private void setUrl(int stringId) {
        mUrl.setText(stringId);
    }

    private void setUrlIcon(int urlIconId) {
        if (mUrlIconId == urlIconId) {
            return;
        }

        mUrlIconId = urlIconId;
        mUrl.setCompoundDrawablesWithIntrinsicBounds(mUrlIconId, 0, mBookmarkIconId, 0);
    }

    private void setFaviconWithUrl(Bitmap favicon, String url) {
        mFavicon.updateImage(favicon, url);
    }

    private void setBookmarkIcon(int bookmarkIconId) {
        if (mBookmarkIconId == bookmarkIconId) {
            return;
        }

        mBookmarkIconId = bookmarkIconId;
        mUrl.setCompoundDrawablesWithIntrinsicBounds(mUrlIconId, 0, mBookmarkIconId, 0);
    }

    /**
     * Stores the page URL, so that we can use it to replace "Switch to tab" if the open
     * tab changes or is closed.
     */
    private void updateDisplayedUrl(String url) {
        mPageUrl = url;
        updateDisplayedUrl();
    }

    /**
     * Replaces the page URL with "Switch to tab" if there is already a tab open with that URL.
     */
    private void updateDisplayedUrl() {
        int tabId = Tabs.getInstance().getTabIdForUrl(mPageUrl);
        if (!mShowIcons || tabId < 0) {
            setUrl(mPageUrl);
            setUrlIcon(NO_ICON);
        } else {
            setUrl(R.string.switch_to_tab);
            setUrlIcon(R.drawable.ic_url_bar_tab);
        }
    }

    public void setShowIcons(boolean showIcons) {
        mShowIcons = showIcons;
    }

    public void updateFromCursor(Cursor cursor) {
        if (cursor == null) {
            return;
        }

        int titleIndex = cursor.getColumnIndexOrThrow(URLColumns.TITLE);
        final String title = cursor.getString(titleIndex);

        int urlIndex = cursor.getColumnIndexOrThrow(URLColumns.URL);
        final String url = cursor.getString(urlIndex);

        // Use the URL instead of an empty title for consistency with the normal URL
        // bar view - this is the equivalent of getDisplayTitle() in Tab.java
        setTitle(TextUtils.isEmpty(title) ? url : title);

        updateDisplayedUrl(url);

        int faviconIndex = cursor.getColumnIndex(URLColumns.FAVICON);
        if (faviconIndex != -1) {
            byte[] b = cursor.getBlob(faviconIndex);

            Bitmap favicon = null;
            if (b != null) {
                Bitmap bitmap = BitmapUtils.decodeByteArray(b);
                if (bitmap != null) {
                    favicon = Favicons.scaleImage(bitmap);
                }
            }

            setFaviconWithUrl(favicon, url);
        } else {
            // If favicons is not on the cursor, try to fetch it from the memory cache
            setFaviconWithUrl(Favicons.getFaviconFromMemCache(url), url);
        }

        // Don't show bookmark/reading list icon, if not needed.
        if (!mShowIcons) {
            return;
        }

        final int bookmarkIdIndex = cursor.getColumnIndex(Combined.BOOKMARK_ID);
        if (bookmarkIdIndex != -1) {
            final long bookmarkId = cursor.getLong(bookmarkIdIndex);
            final int displayIndex = cursor.getColumnIndex(Combined.DISPLAY);

            final int display;
            if (displayIndex != -1) {
                display = cursor.getInt(displayIndex);
            } else {
                display = Combined.DISPLAY_NORMAL;
            }

            // The bookmark id will be 0 (null in database) when the url
            // is not a bookmark.
            if (bookmarkId == 0) {
                setBookmarkIcon(NO_ICON);
            } else if (display == Combined.DISPLAY_READER) {
                setBookmarkIcon(R.drawable.ic_url_bar_reader);
            } else {
                setBookmarkIcon(R.drawable.ic_url_bar_star);
            }
        } else {
            setBookmarkIcon(NO_ICON);
        }
    }
}
