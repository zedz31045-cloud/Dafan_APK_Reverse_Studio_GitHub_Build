package com.dafan.reverse;

import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Bundle;
import android.provider.OpenableColumns;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;
import android.graphics.Typeface;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class MainActivity extends Activity {
    private static final int PICK_APK = 44;
    private Uri selectedUri;
    private File cachedApk;
    private TextView selectedText, outputText;
    private LinearLayout container;
    private String report = "";

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        buildUi();
    }

    private void buildUi() {
        ScrollView scroll = new ScrollView(this);
        container = new LinearLayout(this); container.setOrientation(LinearLayout.VERTICAL);
        container.setPadding(dp(18), dp(20), dp(18), dp(24)); container.setBackgroundColor(0xfff3f6fb);
        scroll.addView(container);
        TextView title = new TextView(this); title.setText("Dafan APK Reverse Studio"); title.setTextSize(23);
        title.setTypeface(Typeface.DEFAULT, Typeface.BOLD); title.setTextColor(0xff12213a); container.addView(title);
        TextView subtitle = new TextView(this); subtitle.setText("APK Analysis • تحليل محلي لملفات APK"); subtitle.setTextSize(14);
        subtitle.setPadding(0,dp(5),0,dp(14)); subtitle.setTextColor(0xff4c5a70); container.addView(subtitle);
        addButton("📦 اختيار ملف APK / Select APK", v -> pickApk());
        selectedText = text("لم يتم اختيار ملف بعد / No file selected");
        addButton("🔎 تحليل الحزمة / Analyze package", v -> analyzePackage());
        addButton("🗂️ عرض محتويات APK / List archive entries", v -> listArchive());
        addButton("🔤 استخراج سلاسل DEX / Extract printable DEX strings", v -> dexStrings());
        addButton("🔐 حساب SHA-256 / Calculate hash", v -> calculateHash());
        addButton("📄 تصدير التقرير إلى Downloads / Export report", v -> exportReport());
        outputText = text("اختر APK للبدء.\nChoose an APK to begin.");
        outputText.setTextIsSelectable(true); outputText.setBackgroundColor(0xffffffff); outputText.setPadding(dp(12),dp(12),dp(12),dp(12));
        container.addView(outputText);
        TextView warning = text("مهم: هذه النسخة تحلل معلومات الحزمة والأرشيف وتعرض سلاسل نصية أولية من DEX. لا تفك تشفير AndroidManifest الثنائي، ولا تعرض Java/Kotlin المصدر الأصلي، ولا تعيد بناء APK. لا يتم رفع ملفاتك إلى الإنترنت.");
        warning.setTextColor(0xff8a3b12); warning.setPadding(0,dp(14),0,0); container.addView(warning);
        setContentView(scroll);
    }

    private TextView text(String value) {
        TextView t = new TextView(this); t.setText(value); t.setTextSize(14); t.setTextColor(0xff243247); t.setPadding(0,dp(9),0,dp(9)); return t;
    }
    private void addButton(String label, View.OnClickListener listener) {
        Button b = new Button(this); b.setText(label); b.setAllCaps(false); b.setOnClickListener(listener);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1,-2); lp.setMargins(0,dp(4),0,dp(4)); container.addView(b,lp);
    }
    private int dp(int v) { return (int)(v*getResources().getDisplayMetrics().density+0.5f); }
    private void pickApk() {
        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT); i.setType("application/vnd.android.package-archive");
        i.addCategory(Intent.CATEGORY_OPENABLE); i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION);
        startActivityForResult(i,PICK_APK);
    }
    @Override protected void onActivityResult(int requestCode,int resultCode,Intent data) {
        super.onActivityResult(requestCode,resultCode,data);
        if(requestCode==45 && resultCode==RESULT_OK && data!=null && data.getData()!=null) {
            try (OutputStream out=getContentResolver().openOutputStream(data.getData())) {
                if(out==null) throw new Exception("Cannot open output file");
                out.write(report.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                toast("تم تصدير التقرير / Report exported");
            } catch(Exception e) { showError("Report export failed: " + e.getMessage()); }
            return;
        }
        if(requestCode==PICK_APK && resultCode==RESULT_OK && data!=null && data.getData()!=null) {
            selectedUri=data.getData();
            try { getContentResolver().takePersistableUriPermission(selectedUri,Intent.FLAG_GRANT_READ_URI_PERMISSION); } catch(Exception ignored) {}
            String name = queryName(selectedUri); selectedText.setText("Selected: " + name + "\n" + selectedUri);
            try { cachedApk = copyToCache(selectedUri,name); outputText.setText("تم اختيار الملف. اختر إحدى عمليات التحليل.\nFile selected. Choose an analysis action."); }
            catch(Exception e) { cachedApk=null; showError("تعذر قراءة الملف: " + e.getMessage()); }
        }
    }
    private String queryName(Uri uri) {
        try(android.database.Cursor c=getContentResolver().query(uri,new String[]{OpenableColumns.DISPLAY_NAME},null,null,null)) {
            if(c!=null && c.moveToFirst()) return c.getString(0);
        } catch(Exception ignored) {} return "selected.apk";
    }
    private File copyToCache(Uri uri,String name) throws Exception {
        File target = new File(getCacheDir(),"selected-analysis.apk");
        try(InputStream in=getContentResolver().openInputStream(uri); OutputStream out=new FileOutputStream(target)) {
            if(in==null) throw new Exception("Input stream unavailable"); byte[] buf=new byte[8192]; int n;
            while((n=in.read(buf))!=-1) out.write(buf,0,n);
        }
        return target;
    }
    private boolean ready() { if(cachedApk==null || !cachedApk.isFile()) { toast("اختر ملف APK أولاً / Select an APK first"); return false; } return true; }
    private void analyzePackage() {
        if(!ready()) return;
        try {
            PackageManager pm=getPackageManager(); PackageInfo pi=pm.getPackageArchiveInfo(cachedApk.getAbsolutePath(),PackageManager.GET_PERMISSIONS | PackageManager.GET_ACTIVITIES | PackageManager.GET_SERVICES | PackageManager.GET_RECEIVERS | PackageManager.GET_PROVIDERS);
            StringBuilder s=new StringBuilder("PACKAGE ANALYSIS / تحليل الحزمة\n\n");
            if(pi==null) s.append("Android PackageManager could not parse package metadata.\nقد يكون الملف تالفًا أو تنسيقه غير مدعوم.\n");
            else {
                s.append("Package: ").append(pi.packageName).append('\n');
                if(android.os.Build.VERSION.SDK_INT>=28) s.append("Version: ").append(pi.getLongVersionCode()).append('\n'); else s.append("Version: ").append(pi.versionCode).append('\n');
                s.append("Version name: ").append(pi.versionName).append('\n');
                s.append("Target SDK: ").append(pi.applicationInfo==null?"unknown":pi.applicationInfo.targetSdkVersion).append('\n');
                s.append("Requested permissions:\n");
                if(pi.requestedPermissions!=null) for(String p:pi.requestedPermissions) s.append(" • ").append(p).append('\n'); else s.append(" (not available)\n");
                s.append("\nComponents reported by PackageManager:\n");
                s.append("Activities: ").append(pi.activities==null?0:pi.activities.length).append('\n');
                s.append("Services: ").append(pi.services==null?0:pi.services.length).append('\n');
                s.append("Receivers: ").append(pi.receivers==null?0:pi.receivers.length).append('\n');
                s.append("Providers: ").append(pi.providers==null?0:pi.providers.length).append('\n');
            }
            report=s.toString(); outputText.setText(report);
        } catch(Exception e) { showError("Package analysis failed: " + e.getMessage()); }
    }
    private void listArchive() {
        if(!ready()) return;
        try(ZipFile z=new ZipFile(cachedApk)) {
            List<String> entries=ApkAnalyzer.listEntries(z); StringBuilder s=new StringBuilder("ARCHIVE CONTENTS / محتويات الأرشيف\nEntries: ").append(entries.size()).append("\n\n");
            int max=Math.min(entries.size(),2500); for(int i=0;i<max;i++) s.append(entries.get(i)).append('\n');
            if(entries.size()>max) s.append("\nOutput limited to first ").append(max).append(" entries.");
            report=s.toString(); outputText.setText(report);
        } catch(Exception e) { showError("ZIP/APK read failed: " + e.getMessage()); }
    }
    private void dexStrings() {
        if(!ready()) return;
        try(ZipFile z=new ZipFile(cachedApk)) {
            List<String> strings=ApkAnalyzer.findDexStrings(z,1000); StringBuilder s=new StringBuilder("PRINTABLE DEX STRINGS / سلاسل نصية أولية\nFound: ").append(strings.size()).append("\n\n");
            for(String value:strings) s.append(value).append('\n');
            if(strings.isEmpty()) s.append("No DEX printable strings found, or APK has no classes*.dex files.");
            s.append("\n\nNote: this is a raw printable-string scan, not decompilation."); report=s.toString(); outputText.setText(report);
        } catch(Exception e) { showError("DEX scan failed: " + e.getMessage()); }
    }
    private void calculateHash() {
        if(!ready()) return;
        try(InputStream in=new FileInputStream(cachedApk)) { report="FILE HASH / بصمة الملف\n\nSHA-256: " + ApkAnalyzer.sha256(in) + "\nSize: " + cachedApk.length() + " bytes\n\nHash computed locally; file was not uploaded."; outputText.setText(report); }
        catch(Exception e) { showError("Hash failed: " + e.getMessage()); }
    }
    private void exportReport() {
        if(report==null || report.isEmpty()) { toast("نفّذ عملية تحليل أولاً / Run analysis first"); return; }
        Intent i=new Intent(Intent.ACTION_CREATE_DOCUMENT); i.addCategory(Intent.CATEGORY_OPENABLE); i.setType("text/plain"); i.putExtra(Intent.EXTRA_TITLE,"Dafan_APK_Analysis_Report.txt");
        startActivityForResult(i,45);
    }
    private void showError(String message) { outputText.setText("ERROR / خطأ\n"+message); toast(message); }
    private void toast(String m) { Toast.makeText(this,m,Toast.LENGTH_LONG).show(); }
}
