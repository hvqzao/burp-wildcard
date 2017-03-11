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
    private final String[] defaultBurpTabs = {"Target", "Proxy", "Spider", "Scanner", "Intruder", "Repeater", "Sequencer", "Decoder", "Comparer", "Extender", "Options", "User options", "Project options", "Alerts", "*"};
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

        callbacks.customizeUiComponent(optionsSettingsUnsupported);
        callbacks.customizeUiComponent(optionsSettingsPersistency);
        callbacks.customizeUiComponent(optionsSettingsShortenTab);
        callbacks.customizeUiComponent(optionsSettingsHijack);
        callbacks.customizeUiComponent(optionsSettingsHelp);
        callbacks.customizeUiComponent(optionsSettingsDefaults);

        extensionTabLabel = new JLabel(getTabCaption());
        callbacks.customizeUiComponent(extensionTabLabel);

        optionsSettingsHelp.setIcon(BurpExtender.getIconHelp());
        optionsSettingsDefaults.setIcon(BurpExtender.getIconDefaults());
        optionsSettingsHelp.setEnabled(false);
        optionsSettingsPersistency.setEnabled(false);
        optionsSettingsShortenTab.setSelected(true);
        optionsSettingsShortenTab.setEnabled(false);
        optionsSettingsHijack.setSelected(true);
        optionsSettingsHijack.setEnabled(false);

        Arrays.stream(defaultBurpTabs).forEach(e -> burpTabs.add(e));
        hijackModel = new ArrayList<>();

        // defaults
        optionsSettingsDefaults.addActionListener((e) -> {
            optionsSettingsUnsupported.setSelected(false);
            optionsSettingsPersistency.setSelected(false);
            optionsSettingsUnsupportedChange();
        });
        // unsupported
        optionsSettingsUnsupported.addActionListener((e) -> {
            optionsSettingsUnsupportedChange();
        });
        // persistency
        optionsSettingsPersistency.addActionListener((e) -> {
            optionsSettingsPersistencySave();
        });
        // shorten
        optionsSettingsShortenTab.addActionListener((e) -> {
            if (optionsSettingsPersistency.isSelected()) {
                callbacks.saveExtensionSetting("optionsSettingsShortenTab", String.valueOf(optionsSettingsShortenTab.isSelected()));
            }
            optionsSettingsShortenTabUpdate();
            extensionTabHighlightOrange();
        });
        // hijack
        optionsSettingsHijack.addActionListener((e) -> {
            if (optionsSettingsPersistency.isSelected()) {
                callbacks.saveExtensionSetting("optionsSettingsHijack", String.valueOf(optionsSettingsHijack.isSelected()));
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
        return optionsSettingsDefaults;
    }

    public JButton getOptionsSettingsHelp() {
        return optionsSettingsHelp;
    }

    public JCheckBox getOptionsSettingsUnsupported() {
        return optionsSettingsUnsupported;
    }

    public JCheckBox getOptionsSettingsPersistency() {
        return optionsSettingsPersistency;
    }

    public JCheckBox getOptionsSettingsShortenTab() {
        return optionsSettingsShortenTab;
    }

    public JLabel getOptionsSettingsTitle() {
        return optionsSettingsTitle;
    }

    public JCheckBox getOptionsSettingsHijack() {
        return optionsSettingsHijack;
    }

    private void optionsSettingsPersistencyLoad() {
        String unsupported = callbacks.loadExtensionSetting("optionsSettingsUnsupported");
        if (unsupported != null) {
            optionsSettingsUnsupported.setEnabled(String.valueOf("true").equals(unsupported));
            optionsSettingsUnsupported.setSelected(true);
            optionsSettingsUnsupportedChange();
            optionsSettingsPersistency.setSelected(true);
            String shortenTab = callbacks.loadExtensionSetting("optionsSettingsShortenTab");
            if (shortenTab != null) {
                optionsSettingsShortenTab.setSelected(String.valueOf("true").equals(shortenTab));
                optionsSettingsShortenTabUpdate();
                extensionTabHighlightOrange();
            }
            String hijack = callbacks.loadExtensionSetting("optionsSettingsHijack");
            if (hijack != null) {
                optionsSettingsHijack.setSelected(String.valueOf("true").equals(hijack));
                optionsSettingsHijackUpdate();
            }
        }
    }

    private void optionsSettingsPersistencySave() {
        if (optionsSettingsPersistency.isSelected()) {
            callbacks.saveExtensionSetting("optionsSettingsUnsupported", String.valueOf(optionsSettingsUnsupported.isSelected()));
            callbacks.saveExtensionSetting("optionsSettingsShortenTab", String.valueOf(optionsSettingsShortenTab.isSelected()));
            callbacks.saveExtensionSetting("optionsSettingsHijack", String.valueOf(optionsSettingsHijack.isSelected()));
        } else {
            callbacks.saveExtensionSetting("optionsSettingsUnsupported", null);
            callbacks.saveExtensionSetting("optionsSettingsShortenTab", null);
            callbacks.saveExtensionSetting("optionsSettingsHijack", null);
        }
        //optionsSettingsPersistencyStatus("save");
    }

    private void optionsSettingsUnsupportedChange() {
        boolean status = optionsSettingsUnsupported.isSelected();
        if (status == false) {
            optionsSettingsShortenTab.setSelected(true);
            optionsSettingsShortenTabUpdate();
        }
        optionsSettingsPersistency.setEnabled(status);
        optionsSettingsShortenTab.setEnabled(status);
        optionsSettingsHijack.setEnabled(status);
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
        if (optionsSettingsHijack.isEnabled() && optionsSettingsHijack.isSelected()) {
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
        boolean status = optionsSettingsUnsupported.isSelected();
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
        extensionTabLabel.setForeground(new Color(229, 137, 0));
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

        optionsSettingsHelp = new javax.swing.JButton();
        optionsSettingsDefaults = new javax.swing.JButton();
        optionsSettingsTitle = new javax.swing.JLabel();
        optionsSettingsDescription = new javax.swing.JLabel();
        optionsSettingsUnsupported = new javax.swing.JCheckBox();
        optionsSettingsPersistency = new javax.swing.JCheckBox();
        optionsSettingsShortenTab = new javax.swing.JCheckBox();
        optionsSettingsHijack = new javax.swing.JCheckBox();

        setBorder(javax.swing.BorderFactory.createEmptyBorder(5, 5, 5, 5));

        optionsSettingsHelp.setMargin(new java.awt.Insets(0, 0, 0, 0));
        optionsSettingsHelp.setMaximumSize(new java.awt.Dimension(24, 24));
        optionsSettingsHelp.setMinimumSize(new java.awt.Dimension(24, 24));
        optionsSettingsHelp.setPreferredSize(new java.awt.Dimension(24, 24));

        optionsSettingsDefaults.setMargin(new java.awt.Insets(0, 0, 0, 0));
        optionsSettingsDefaults.setMaximumSize(new java.awt.Dimension(24, 24));
        optionsSettingsDefaults.setMinimumSize(new java.awt.Dimension(24, 24));
        optionsSettingsDefaults.setPreferredSize(new java.awt.Dimension(24, 24));

        optionsSettingsTitle.setText("<html><b style='color:#e58900;font-size:10px'>Settings</b></html>");

        optionsSettingsDescription.setText("<html>Use these settings to control extension behavior.</html>");

        optionsSettingsUnsupported.setText("Enable features not officially supported by Burp Extender");

        optionsSettingsPersistency.setText("Remember those settings (potentially unsafe)");

        optionsSettingsShortenTab.setText("Shorten extension name on main tab");

        optionsSettingsHijack.setText("Hijack tabs belonging to other extensions");

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(optionsSettingsHelp, javax.swing.GroupLayout.PREFERRED_SIZE, 24, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(optionsSettingsTitle, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(optionsSettingsDefaults, javax.swing.GroupLayout.PREFERRED_SIZE, 24, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(optionsSettingsDescription, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(optionsSettingsUnsupported)
                            .addGroup(layout.createSequentialGroup()
                                .addGap(21, 21, 21)
                                .addComponent(optionsSettingsPersistency))
                            .addComponent(optionsSettingsShortenTab)
                            .addComponent(optionsSettingsHijack))))
                .addContainerGap(339, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(optionsSettingsHelp, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(optionsSettingsDefaults, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(optionsSettingsTitle, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(optionsSettingsDescription, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(optionsSettingsUnsupported)))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(optionsSettingsPersistency)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(optionsSettingsShortenTab)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(optionsSettingsHijack)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
    }// </editor-fold>//GEN-END:initComponents


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton optionsSettingsDefaults;
    private javax.swing.JLabel optionsSettingsDescription;
    private javax.swing.JButton optionsSettingsHelp;
    private javax.swing.JCheckBox optionsSettingsHijack;
    private javax.swing.JCheckBox optionsSettingsPersistency;
    private javax.swing.JCheckBox optionsSettingsShortenTab;
    private javax.swing.JLabel optionsSettingsTitle;
    private javax.swing.JCheckBox optionsSettingsUnsupported;
    // End of variables declaration//GEN-END:variables

    //
    // implement ITab
    //
    @Override
    public String getTabCaption() {
        if (optionsSettingsShortenTab.isSelected()) {
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
