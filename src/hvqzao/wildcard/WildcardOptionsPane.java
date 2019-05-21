package hvqzao.wildcard;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionStateListener;
import burp.ITab;
import java.awt.Color;
import java.awt.Component;
import java.awt.event.ActionEvent;
import java.util.ArrayList;
import java.util.Arrays;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.Timer;

public class WildcardOptionsPane extends JPanel implements ITab, IExtensionStateListener {

    private IBurpExtenderCallbacks callbacks;
    private Component extensionTabLabelRestore;
    private ArrayList<String> hijackModel;
    private final String[] defaultBurpTabs = {"Dashboard", "Target", "Proxy", "Spider", "Scanner", "Intruder", "Repeater", "Sequencer", "Decoder", "Comparer", "Extender", "Options", "User options", "Project options", "Alerts", "*"};
    private final ArrayList<String> burpTabs = new ArrayList<>();
    private final JTabbedPane extensionTabbedPane;
    private JTabbedPane burpTabbedPane;
    private Timer hijackTimer;
    private JLabel extensionTabLabel;
    private Timer extensionTabHighlightTimer;

    public WildcardOptionsPane(JTabbedPane extensionTabbedPane) {
        initComponents();

        this.extensionTabbedPane = extensionTabbedPane;
        initialize();
    }

    private void initialize() {
        callbacks = BurpExtender.getCallbacks();

        callbacks.customizeUiComponent(settingsUnsupported);
        callbacks.customizeUiComponent(settingsPersistency);
        callbacks.customizeUiComponent(settingsShortenTab);
        callbacks.customizeUiComponent(settingsHijack);
        callbacks.customizeUiComponent(settingsHelp);
        callbacks.customizeUiComponent(settingsDefaults);

        extensionTabLabel = new JLabel(getTabCaption());
        callbacks.customizeUiComponent(extensionTabLabel);

        settingsHelp.setIcon(BurpExtender.getIconHelp());
        settingsDefaults.setIcon(BurpExtender.getIconDefaults());
        settingsHelp.setEnabled(false);
        settingsPersistency.setEnabled(false);
        settingsShortenTab.setSelected(true);
        settingsShortenTab.setEnabled(false);
        settingsHijack.setSelected(true);
        settingsHijack.setEnabled(false);

        Arrays.stream(defaultBurpTabs).forEach(e -> burpTabs.add(e));
        hijackModel = new ArrayList<>();

        // defaults
        settingsDefaults.addActionListener((e) -> {
            settingsUnsupported.setSelected(false);
            settingsPersistency.setSelected(false);
            optionsSettingsUnsupportedChange();
        });
        // unsupported
        settingsUnsupported.addActionListener((e) -> {
            optionsSettingsUnsupportedChange();
        });
        // persistency
        settingsPersistency.addActionListener((e) -> {
            optionsSettingsPersistencySave();
        });
        // shorten
        settingsShortenTab.addActionListener((e) -> {
            if (settingsPersistency.isSelected()) {
                callbacks.saveExtensionSetting("optionsSettingsShortenTab", String.valueOf(settingsShortenTab.isSelected()));
            }
            optionsSettingsShortenTabUpdate();
            extensionTabHighlightOrange();
        });
        // hijack
        settingsHijack.addActionListener((e) -> {
            if (settingsPersistency.isSelected()) {
                callbacks.saveExtensionSetting("optionsSettingsHijack", String.valueOf(settingsHijack.isSelected()));
            }
            optionsSettingsHijackUpdate();
        });
    }

    /**
     * Activate functionalities
     *
     */
    public void start() {
        callbacks.addSuiteTab(this);
        burpTabbedPane = (JTabbedPane) extensionTabbedPane.getParent();
        callbacks.registerExtensionStateListener(this);
        requestFocus();
        optionsSettingsPersistencyLoad();
    }

    public JButton getOptionsSettingsDefaults() {
        return settingsDefaults;
    }

    public JButton getOptionsSettingsHelp() {
        return settingsHelp;
    }

    public JCheckBox getOptionsSettingsUnsupported() {
        return settingsUnsupported;
    }

    public JCheckBox getOptionsSettingsPersistency() {
        return settingsPersistency;
    }

    public JCheckBox getOptionsSettingsShortenTab() {
        return settingsShortenTab;
    }

    public JLabel getOptionsSettingsTitle() {
        return settingsTitle;
    }

    public JCheckBox getOptionsSettingsHijack() {
        return settingsHijack;
    }

    private void optionsSettingsPersistencyLoad() {
        String unsupported = callbacks.loadExtensionSetting("optionsSettingsUnsupported");
        if (unsupported != null) {
            settingsUnsupported.setEnabled(String.valueOf("true").equals(unsupported));
            settingsUnsupported.setSelected(true);
            optionsSettingsUnsupportedChange();
            settingsPersistency.setSelected(true);
            String shortenTab = callbacks.loadExtensionSetting("optionsSettingsShortenTab");
            if (shortenTab != null) {
                settingsShortenTab.setSelected(String.valueOf("true").equals(shortenTab));
                optionsSettingsShortenTabUpdate();
                extensionTabHighlightOrange();
            }
            String hijack = callbacks.loadExtensionSetting("optionsSettingsHijack");
            if (hijack != null) {
                settingsHijack.setSelected(String.valueOf("true").equals(hijack));
                optionsSettingsHijackUpdate();
            }
        }
    }

    private void optionsSettingsPersistencySave() {
        if (settingsPersistency.isSelected()) {
            callbacks.saveExtensionSetting("optionsSettingsUnsupported", String.valueOf(settingsUnsupported.isSelected()));
            callbacks.saveExtensionSetting("optionsSettingsShortenTab", String.valueOf(settingsShortenTab.isSelected()));
            callbacks.saveExtensionSetting("optionsSettingsHijack", String.valueOf(settingsHijack.isSelected()));
        } else {
            callbacks.saveExtensionSetting("optionsSettingsUnsupported", null);
            callbacks.saveExtensionSetting("optionsSettingsShortenTab", null);
            callbacks.saveExtensionSetting("optionsSettingsHijack", null);
        }
        //optionsSettingsPersistencyStatus("save");
    }

    private void optionsSettingsUnsupportedChange() {
        boolean status = settingsUnsupported.isSelected();
        if (status == false) {
            settingsShortenTab.setSelected(true);
            optionsSettingsShortenTabUpdate();
        }
        settingsPersistency.setEnabled(status);
        settingsShortenTab.setEnabled(status);
        settingsHijack.setEnabled(status);
        extensionTabLabelControlChange(false);
        optionsSettingsHijackUpdate();
    }

    private void hijackTabs() {
        for (int i = 0; i < burpTabbedPane.getTabCount(); i++) {
            String tabName = null;
            try {
                tabName = burpTabbedPane.getTitleAt(i);
            } catch (Exception ex) {
                // do nothing
            } finally {
                if (tabName != null) {
                    boolean regularBurpTab = false;
                    for (String tab : burpTabs) {
                        if (tabName.equals(tab)) {
                            regularBurpTab = true;
                        }
                    }
                    if (!regularBurpTab) {
                        //hijackModel.addElement(tabName);
                        hijackModel.add(tabName);
                    }
                }
            }
        }
        for (int i = 0; i < hijackModel.size(); i++) {
            //String tabName = hijackModel.getElementAt(i);
            String tabName = hijackModel.get(i);
            for (int j = 0; j < burpTabbedPane.getTabCount(); j++) {
                String burpTabName = null;
                try {
                    burpTabName = burpTabbedPane.getTitleAt(j);
                } catch (Exception ex) {
                    // do nothing
                }
                if (burpTabName != null && burpTabName.equals(tabName)) {
                    Component tabComponent = burpTabbedPane.getComponentAt(j);
                    extensionTabbedPane.addTab(tabName, tabComponent);
                    extensionTabHighlightOrange();
                    break;
                }
            }
        }
    }

    private void releaseTabs(boolean transfer) {
        for (int i = 0; i < hijackModel.size(); i++) {
            //String tabName = hijackModel.getElementAt(i);
            String tabName = hijackModel.get(i);
            for (int j = 0; j < extensionTabbedPane.getTabCount(); j++) {
                String extensionTabName = null;
                try {
                    extensionTabName = extensionTabbedPane.getTitleAt(j);
                } catch (Exception ex) {
                    // do nothing
                }
                if (extensionTabName != null && extensionTabName.equals(tabName)) {
                    if (transfer) {
                        Component tabComponent = extensionTabbedPane.getComponentAt(j);
                        burpTabbedPane.addTab(tabName, tabComponent);
                        extensionTabHighlightOrange();
                    } else {
                        extensionTabbedPane.remove(j);
                    }
                    break;
                }
            }
        }
        hijackModel.clear();
    }

    private void optionsSettingsHijackUpdate() {
        if (settingsHijack.isEnabled() && settingsHijack.isSelected()) {
            hijackTabs();
            if (hijackTimer == null) {
                hijackTimer = new Timer(1000, (ActionEvent e) -> {
                    // get list of new Burp UI tabs
                    boolean unhandledTabs = false;
                    for (int i = 0; i < burpTabbedPane.getTabCount(); i++) {
                        String tabName = null;
                        try {
                            tabName = burpTabbedPane.getTitleAt(i);
                        } catch (Exception ex) {
                            // do nothing
                        } finally {
                            if (tabName != null) {
                                boolean regularBurpTab = false;
                                for (String tab : burpTabs) {
                                    if (tabName.equals(tab)) {
                                        regularBurpTab = true;
                                    }
                                }
                                if (!regularBurpTab) {
                                    unhandledTabs = true;
                                }
                            }
                        }
                    }

                    if (unhandledTabs) {
                        extensionTabLabelControlChange(true);
                        releaseTabs(false);
                        hijackTabs();
                    }
                });
                hijackTimer.setRepeats(true);
                hijackTimer.start();
            }
        } else {
            releaseTabs(true);
            if (hijackTimer != null) {
                hijackTimer.stop();
                hijackTimer = null;
            }
        }
    }

    private void optionsSettingsShortenTabUpdate() {
        extensionTabLabel.setText(getTabCaption());
    }

    // extension tab label control change
    private void extensionTabLabelControlChange(boolean unhandled) {
        boolean status = settingsUnsupported.isSelected();
        int extensionTabIndex = -1;
        for (int i = 0; i < burpTabbedPane.getTabCount(); i++) {
            if (status == false) {
                if (burpTabbedPane.getTabComponentAt(i) == extensionTabLabel) {
                    extensionTabIndex = i;
                    break;
                }
            }
            try {
                if (unhandled) {
                    if (burpTabbedPane.getTitleAt(i).equals("*")) {
                        extensionTabIndex = i;
                        break;
                    }
                } else {
                    if (burpTabbedPane.getTitleAt(i).equals(getTabCaption())) {
                        extensionTabIndex = i;
                        break;
                    }
                }
            } catch (Exception ex) {
                //extensionTabIndex = i;
                // do nothing
            }
        }
        if (extensionTabIndex > -1) {
            if (status) {
                if (extensionTabLabelRestore == null) {
                    extensionTabLabelRestore = (Component) burpTabbedPane.getTabComponentAt(extensionTabIndex);
                }
                burpTabbedPane.setTabComponentAt(extensionTabIndex, extensionTabLabel);
            } else {
                if (extensionTabLabelRestore != null) {
                    burpTabbedPane.setTabComponentAt(extensionTabIndex, extensionTabLabelRestore);
                    // burpTabbedPane.setTabComponentAt(extensionTabIndex, null);
                }
            }
        }
        //extensionTabLabel = null;
        //extensionTabLabelRestore = null;
    }

    // extension tab orange label blink
    private void extensionTabHighlightOrange() {
        if (extensionTabHighlightTimer != null) {
            try {
                extensionTabHighlightTimer.stop();
            } catch (Exception ex) {
                // do nothing
            }
        }
        extensionTabHighlightTimer = new Timer(4000, (ActionEvent e) -> {
            extensionTabLabel.setForeground(Color.black);
            extensionTabHighlightTimer = null;
        });
        //extensionTabLabel.setForeground(new Color(229, 137, 0));
        extensionTabLabel.setForeground(new Color(255, 102, 51));
        extensionTabHighlightTimer.setRepeats(false);
        extensionTabHighlightTimer.start();
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        settingsHelp = new javax.swing.JButton();
        settingsDefaults = new javax.swing.JButton();
        settingsTitle = new javax.swing.JLabel();
        settingsDescription = new javax.swing.JLabel();
        settingsUnsupported = new javax.swing.JCheckBox();
        settingsPersistency = new javax.swing.JCheckBox();
        settingsShortenTab = new javax.swing.JCheckBox();
        settingsHijack = new javax.swing.JCheckBox();

        setBorder(javax.swing.BorderFactory.createEmptyBorder(5, 5, 5, 5));

        settingsHelp.setMargin(new java.awt.Insets(0, 0, 0, 0));
        settingsHelp.setMaximumSize(new java.awt.Dimension(24, 24));
        settingsHelp.setMinimumSize(new java.awt.Dimension(24, 24));
        settingsHelp.setPreferredSize(new java.awt.Dimension(24, 24));

        settingsDefaults.setMargin(new java.awt.Insets(0, 0, 0, 0));
        settingsDefaults.setMaximumSize(new java.awt.Dimension(24, 24));
        settingsDefaults.setMinimumSize(new java.awt.Dimension(24, 24));
        settingsDefaults.setPreferredSize(new java.awt.Dimension(24, 24));

        settingsTitle.setText("<html><b style='color:#ff6633;font-size:10px'>Settings</b></html>");

        settingsDescription.setText("<html>Use these settings to control extension behavior.</html>");

        settingsUnsupported.setText("Enable features not officially supported by Burp Extender");

        settingsPersistency.setText("Remember those settings (potentially unsafe)");

        settingsShortenTab.setText("Shorten extension name on main tab");

        settingsHijack.setText("Hijack tabs belonging to other extensions");

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(settingsHelp, javax.swing.GroupLayout.PREFERRED_SIZE, 24, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(settingsTitle, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(settingsDefaults, javax.swing.GroupLayout.PREFERRED_SIZE, 24, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(settingsDescription, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(settingsUnsupported)
                            .addGroup(layout.createSequentialGroup()
                                .addGap(21, 21, 21)
                                .addComponent(settingsPersistency))
                            .addComponent(settingsShortenTab)
                            .addComponent(settingsHijack))))
                .addGap(0, 349, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(settingsHelp, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(settingsTitle, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(settingsDescription, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(settingsUnsupported)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(settingsPersistency)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(settingsShortenTab)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(settingsHijack))
                    .addComponent(settingsDefaults, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap())
        );
    }// </editor-fold>//GEN-END:initComponents


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton settingsDefaults;
    private javax.swing.JLabel settingsDescription;
    private javax.swing.JButton settingsHelp;
    private javax.swing.JCheckBox settingsHijack;
    private javax.swing.JCheckBox settingsPersistency;
    private javax.swing.JCheckBox settingsShortenTab;
    private javax.swing.JLabel settingsTitle;
    private javax.swing.JCheckBox settingsUnsupported;
    // End of variables declaration//GEN-END:variables

    //
    // implement ITab
    //
    @Override
    public String getTabCaption() {
        if (settingsShortenTab.isSelected()) {
            return "*";
        } else {
            return "Wildcard";
        }
    }

    @Override
    public Component getUiComponent() {
        return extensionTabbedPane;
    }

    //
    // implement IExtensionStateListener
    //
    @Override
    public void extensionUnloaded() {
        if (extensionTabHighlightTimer != null) {
            try {
                extensionTabHighlightTimer.stop();
                extensionTabHighlightTimer = null;
            } catch (Exception ex) {
                // do nothing
            }
        }
        if (hijackTimer != null) {
            try {
                hijackTimer.stop();
                hijackTimer = null;
            } catch (Exception ex) {
                // do nothing
            }
        }
    }
}
