// The source of `receiver.dex` next to it, which `receiver.rs` loads at run time.
// `cargo xtask android-dex` rebuilds the dex from this file, and `--check` fails when the
// two disagree.
package proxywatch;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

public final class ProxyChangeReceiver extends BroadcastReceiver {
    private final long id;

    public ProxyChangeReceiver(long id) {
        this.id = id;
    }

    @Override
    public void onReceive(Context context, Intent intent) {
        changed(id);
    }

    // Bound with RegisterNatives: the class lives in its own class loader, where the
    // library's exported symbols are never looked up.
    private static native void changed(long id);
}
