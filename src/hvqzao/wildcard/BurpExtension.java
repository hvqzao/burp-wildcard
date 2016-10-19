// Wildcard Burp Extension, (c) 2015-2016 Marcin Woloszyn (@hvqzao), Released under MIT license
package hvqzao.wildcard;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IExtensionStateListener;
import burp.ITab;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.util.ArrayList;

import javax.swing.BorderFactory;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingUtilities;
import javax.swing.Timer;

public class BurpExtension implements IBurpExtender, ITab, IExtensionStateListener {

    private static IBurpExtenderCallbacks callbacks;
    private static IExtensionHelpers helpers;
    private JTabbedPane extensionTabbedPane;
    private JLabel extensionTabLabel;
    private Component extensionTabLabelRestore;
    private Timer extensionTabHighlightTimer;
    //private JFrame burpFrame;
    private JTabbedPane burpTabbedPane;
    // private DefaultListModel<String> hijackModel;
    private ArrayList<String> hijackModel;
    private JCheckBox optionsSettingsUnsupported;
    private JCheckBox optionsSettingsPersistency;
    private JCheckBox optionsSettingsShortenTab;
    private final String[] burpTabs = {"Target", "Proxy", "Spider", "Scanner", "Intruder", "Repeater", "Sequencer", "Decoder", "Comparer", "Extender", "Options", "User options", "Project options", "Alerts", "*"};
    private JCheckBox optionsSettingsHijack;
    private final ArrayList<JDialog> dialogs = new ArrayList<>();
    private Timer hijackTimer;

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        // keep a reference to our callbacks object
        BurpExtension.callbacks = callbacks;
        // your extension code here
        // obtain an extension helpers object
        helpers = callbacks.getHelpers();
        // set extension name
        callbacks.setExtensionName("Wildcard");
        // draw UI
        SwingUtilities.invokeLater(new Runnable() {

            @Override
            public void run() {
                // images
                ImageIcon iconHelp = new ImageIcon(new ImageIcon(getClass().getResource("/hvqzao/wildcard/resources/panel_help.png")).getImage().getScaledInstance(13, 13, java.awt.Image.SCALE_SMOOTH));
                ImageIcon iconDefaults = new ImageIcon(new ImageIcon(getClass().getResource("/hvqzao/wildcard/resources/panel_defaults.png")).getImage().getScaledInstance(13, 13, java.awt.Image.SCALE_SMOOTH));
                Dimension iconDimension = new Dimension(24, 24);
                // main tab
                // extensionTabbedPane = new JTabbedPane();
                extensionTabbedPane = new DnDTabbedPane();
                callbacks.customizeUiComponent(extensionTabbedPane);

                // options tab
//                final JPanel optionsPane = new JPanel();
                final OptionsPane optionsPane = new OptionsPane();
                // options layout
//                SpringLayout optionsLayout = new SpringLayout();
//                optionsPane.setLayout(optionsLayout);
                // options settings
//                JButton optionsSettingsHelp = new JButton(iconHelp);
                JButton optionsSettingsHelp = optionsPane.getOptionsSettingsHelp();
                optionsSettingsHelp.setIcon(iconHelp);
                callbacks.customizeUiComponent(optionsSettingsHelp);
//                JButton optionsSettingsHelp = new JButton(iconHelp);
//                optionsLayout.putConstraint(SpringLayout.NORTH, optionsSettingsHelp, 10, SpringLayout.NORTH, optionsPane);
//                optionsLayout.putConstraint(SpringLayout.WEST, optionsSettingsHelp, 10, SpringLayout.WEST, optionsPane);
//                optionsSettingsHelp.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0));
//                optionsSettingsHelp.setPreferredSize(iconDimension);
//                optionsSettingsHelp.setMaximumSize(iconDimension);
                optionsSettingsHelp.setEnabled(false);
//                optionsPane.add(optionsSettingsHelp);
//                //
//                JButton optionsSettingsDefaults = new JButton(iconDefaults);
                JButton optionsSettingsDefaults = optionsPane.getOptionsSettingsDefaults();
                optionsSettingsDefaults.setIcon(iconDefaults);
                callbacks.customizeUiComponent(optionsSettingsDefaults);
//                optionsLayout.putConstraint(SpringLayout.NORTH, optionsSettingsDefaults, 5, SpringLayout.SOUTH, optionsSettingsHelp);
//                optionsLayout.putConstraint(SpringLayout.WEST, optionsSettingsDefaults, 10, SpringLayout.WEST, optionsPane);
//                optionsSettingsDefaults.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0));
//                optionsSettingsDefaults.setPreferredSize(iconDimension);
//                optionsSettingsDefaults.setMaximumSize(iconDimension);
//                optionsPane.add(optionsSettingsDefaults);
//                //
//                final JLabel optionsSettingsTitle = new JLabel("<html><b style='color:#e58900;font-size:10px'>Settings</b></html>");
                final JLabel optionsSettingsTitle = optionsPane.getOptionsSettingsTitle();
//                optionsLayout.putConstraint(SpringLayout.NORTH, optionsSettingsTitle, 0, SpringLayout.NORTH, optionsSettingsHelp);
//                optionsLayout.putConstraint(SpringLayout.WEST, optionsSettingsTitle, 12, SpringLayout.EAST, optionsSettingsHelp);
//                optionsPane.add(optionsSettingsTitle);
//                //
//                JLabel optionsSettingsDescription = new JLabel("<html>Use these settings to control extension behavior.</html>");
                final JLabel optionsSettingsDescription = optionsPane.getOptionsSettingsDescription();
//                optionsLayout.putConstraint(SpringLayout.NORTH, optionsSettingsDescription, 10, SpringLayout.SOUTH, optionsSettingsTitle);
//                optionsLayout.putConstraint(SpringLayout.WEST, optionsSettingsDescription, 0, SpringLayout.WEST, optionsSettingsTitle);
//                optionsLayout.putConstraint(SpringLayout.EAST, optionsSettingsDescription, -10, SpringLayout.EAST, optionsPane);
//                // optionsFilterDescription.setVerticalAlignment(SwingConstants.TOP);
//                optionsPane.add(optionsSettingsDescription);
//                //
//                optionsSettingsUnsupported = new JCheckBox("Enable features not officially supported by Burp Extender");
                optionsSettingsUnsupported = optionsPane.getOptionsSettingsUnsupported();
//                optionsLayout.putConstraint(SpringLayout.NORTH, optionsSettingsUnsupported, 15, SpringLayout.SOUTH, optionsSettingsDescription);
//                optionsLayout.putConstraint(SpringLayout.WEST, optionsSettingsUnsupported, 0, SpringLayout.WEST, optionsSettingsTitle);
                // optionsSettingsUnsupported.setSelected(true);
                callbacks.customizeUiComponent(optionsSettingsUnsupported);
//                optionsPane.add(optionsSettingsUnsupported);
//                //
//                optionsSettingsPersistency = new JCheckBox("Remember those settings (potentially unsafe)");
                optionsSettingsPersistency = optionsPane.getOptionsSettingsPersistency();
//                optionsLayout.putConstraint(SpringLayout.NORTH, optionsSettingsPersistency, 5, SpringLayout.SOUTH, optionsSettingsUnsupported);
//                optionsLayout.putConstraint(SpringLayout.WEST, optionsSettingsPersistency, 20, SpringLayout.WEST, optionsSettingsTitle);
                callbacks.customizeUiComponent(optionsSettingsPersistency);
                optionsSettingsPersistency.setEnabled(false);
//                optionsPane.add(optionsSettingsPersistency);
//                //
//                optionsSettingsShortenTab = new JCheckBox("Shorten extension name on main tab");
                optionsSettingsShortenTab = optionsPane.getOptionsSettingsShortenTab();
//                optionsLayout.putConstraint(SpringLayout.NORTH, optionsSettingsShortenTab, 5, SpringLayout.SOUTH, optionsSettingsPersistency);
//                optionsLayout.putConstraint(SpringLayout.WEST, optionsSettingsShortenTab, 0, SpringLayout.WEST, optionsSettingsTitle);
                optionsSettingsShortenTab.setSelected(true);
                callbacks.customizeUiComponent(optionsSettingsShortenTab);
                optionsSettingsShortenTab.setEnabled(false);
//                optionsPane.add(optionsSettingsShortenTab);
                optionsSettingsShortenTab.addActionListener(new ActionListener() {

                    @Override
                    public void actionPerformed(ActionEvent e) {
                        if (optionsSettingsPersistency.isSelected()) {
                            callbacks.saveExtensionSetting("optionsSettingsShortenTab", String.valueOf(optionsSettingsShortenTab.isSelected()));
                        }
                        optionsSettingsShortenTabUpdate();
                        extensionTabHighlightOrange();
                    }
                });
//                //
//                optionsSettingsHijack = new JCheckBox("Hijack tabs belonging to other extensions");
                optionsSettingsHijack = optionsPane.getOptionsSettingsHijack();
//                optionsLayout.putConstraint(SpringLayout.NORTH, optionsSettingsHijack, 5, SpringLayout.SOUTH, optionsSettingsShortenTab);
//                optionsLayout.putConstraint(SpringLayout.WEST, optionsSettingsHijack, 0, SpringLayout.WEST, optionsSettingsTitle);
                optionsSettingsHijack.setSelected(true);
                callbacks.customizeUiComponent(optionsSettingsHijack);
                optionsSettingsHijack.setEnabled(false);
//                optionsPane.add(optionsSettingsHijack);
                optionsSettingsHijack.addActionListener(new ActionListener() {

                    @Override
                    public void actionPerformed(ActionEvent e) {
                        if (optionsSettingsPersistency.isSelected()) {
                            callbacks.saveExtensionSetting("optionsSettingsHijack", String.valueOf(optionsSettingsHijack.isSelected()));
                        }
                        optionsSettingsHijackUpdate();
                    }
                });
                ////
                //JSeparator optionsSettingsSeparator = new JSeparator();
                //optionsLayout.putConstraint(SpringLayout.NORTH, optionsSettingsSeparator, 21, SpringLayout.SOUTH, optionsSettingsHijack);
                //optionsLayout.putConstraint(SpringLayout.WEST, optionsSettingsSeparator, 10, SpringLayout.WEST, optionsPane);
                //optionsLayout.putConstraint(SpringLayout.EAST, optionsSettingsSeparator, -10, SpringLayout.EAST, optionsPane);
                //optionsPane.add(optionsSettingsSeparator);
                //// Helpers
                //final JButton optionsHelpersHelp = new JButton(iconHelp);
                //optionsLayout.putConstraint(SpringLayout.NORTH, optionsHelpersHelp, 21, SpringLayout.NORTH, optionsSettingsSeparator);
                //optionsLayout.putConstraint(SpringLayout.WEST, optionsHelpersHelp, 10, SpringLayout.WEST, optionsPane);
                //optionsHelpersHelp.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0));
                //optionsHelpersHelp.setPreferredSize(iconDimension);
                //optionsHelpersHelp.setMaximumSize(iconDimension);
                //optionsHelpersHelp.setEnabled(false);
                //optionsPane.add(optionsHelpersHelp);
                ////
                //JButton optionsHelpersDefaults = new JButton(iconDefaults);
                //optionsLayout.putConstraint(SpringLayout.NORTH, optionsHelpersDefaults, 5, SpringLayout.SOUTH, optionsHelpersHelp);
                //optionsLayout.putConstraint(SpringLayout.WEST, optionsHelpersDefaults, 10, SpringLayout.WEST, optionsPane);
                //optionsHelpersDefaults.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0));
                //optionsHelpersDefaults.setPreferredSize(iconDimension);
                //optionsHelpersDefaults.setMaximumSize(iconDimension);
                //optionsHelpersDefaults.setEnabled(false);
                //optionsPane.add(optionsHelpersDefaults);
                ////
                //final JLabel optionsHelpersTitle = new JLabel("<html><b style='color:#e58900;font-size:10px'>Helpers</b></html>");
                //optionsLayout.putConstraint(SpringLayout.NORTH, optionsHelpersTitle, 0, SpringLayout.NORTH, optionsHelpersHelp);
                //optionsLayout.putConstraint(SpringLayout.WEST, optionsHelpersTitle, 12, SpringLayout.EAST, optionsHelpersHelp);
                //optionsPane.add(optionsHelpersTitle);
                ////
                //JLabel optionsHelpersDescription = new JLabel("<html>From here you might access sources of mini-extensions which act" + " as helpers for testing specific web applications. Those extensions were written in Python so they can be easily"
                //        + " customized, saved in working folder and loaded into Burp without need of recompilation.</html>");
                //optionsLayout.putConstraint(SpringLayout.NORTH, optionsHelpersDescription, 10, SpringLayout.SOUTH, optionsHelpersTitle);
                //optionsLayout.putConstraint(SpringLayout.WEST, optionsHelpersDescription, 0, SpringLayout.WEST, optionsHelpersTitle);
                //optionsLayout.putConstraint(SpringLayout.EAST, optionsHelpersDescription, -10, SpringLayout.EAST, optionsPane);
                //optionsPane.add(optionsHelpersDescription);
                ////
                //final JCheckBox optionsHelpersCSRF = new JCheckBox("<html><i style='color:#e58900'>CSRF Handling</i> Burp Extension (Python)</html>");
                //optionsLayout.putConstraint(SpringLayout.NORTH, optionsHelpersCSRF, 15, SpringLayout.SOUTH, optionsHelpersDescription);
                //optionsLayout.putConstraint(SpringLayout.WEST, optionsHelpersCSRF, 0, SpringLayout.WEST, optionsHelpersTitle);
                //optionsLayout.putConstraint(SpringLayout.EAST, optionsHelpersCSRF, -10, SpringLayout.EAST, optionsPane);
                //callbacks.customizeUiComponent(optionsHelpersCSRF);
                //optionsPane.add(optionsHelpersCSRF);
                //optionsHelpersCSRF.addActionListener(new ActionListener() {
                //
                //    @Override
                //    public void actionPerformed(ActionEvent e) {
                //        if (optionsHelpersCSRF.isSelected()) {
                //            optionsHelpersCSRF.setSelected(false);
                //            new HelperView(burpFrame, "CSRF Handling Burp Extension (Python)", "csrf_handling.py", helpers.bytesToString(streamToBytes(getClass().getResourceAsStream("/hvqzao/wildcard/resources/csrf_handling.py"))));
                //        }
                //    }
                //});
                ////
                //JLabel optionsHelpersCSRFDescription = new JLabel("<html>This extension should handle application specific CSRF tokens in order to enable it for automated testing."
                //        + "There are separate settings also available for literal string replacement in requests and responses. Thanks to that there is no need to mess in global Burp proxy search and replace settings.</html>");
                //optionsLayout.putConstraint(SpringLayout.NORTH, optionsHelpersCSRFDescription, 3, SpringLayout.SOUTH, optionsHelpersCSRF);
                //optionsLayout.putConstraint(SpringLayout.WEST, optionsHelpersCSRFDescription, 20, SpringLayout.WEST, optionsHelpersCSRF);
                //optionsLayout.putConstraint(SpringLayout.EAST, optionsHelpersCSRFDescription, -10, SpringLayout.EAST, optionsPane);
                //optionsPane.add(optionsHelpersCSRFDescription);
                //// options height measurement component
                //final JPanel optionsPaneHeight = new JPanel();
                //optionsLayout.putConstraint(SpringLayout.NORTH, optionsPaneHeight, 0, SpringLayout.NORTH, optionsPane);
                //optionsLayout.putConstraint(SpringLayout.SOUTH, optionsPaneHeight, 0, SpringLayout.SOUTH, optionsSettingsShortenTab);
                //optionsLayout.putConstraint(SpringLayout.WEST, optionsPaneHeight, 0, SpringLayout.WEST, optionsPane);
                //optionsLayout.putConstraint(SpringLayout.EAST, optionsPaneHeight, 0, SpringLayout.WEST, optionsPane);
                //optionsPane.add(optionsPaneHeight);

                // settings defaults
                optionsSettingsDefaults.addActionListener(new ActionListener() {

                    @Override
                    public void actionPerformed(ActionEvent e) {
                        optionsSettingsUnsupported.setSelected(false);
                        optionsSettingsPersistency.setSelected(false);
                        optionsSettingsUnsupportedChange();
                    }
                });
                // options Unsupported
                optionsSettingsUnsupported.addActionListener(new ActionListener() {

                    @Override
                    public void actionPerformed(ActionEvent e) {
                        optionsSettingsUnsupportedChange();
                    }
                });
                // options Persistency
                optionsSettingsPersistency.addActionListener(new ActionListener() {

                    @Override
                    public void actionPerformed(ActionEvent e) {
                        optionsSettingsPersistencySave();
                    }
                });
                // options epilog
                JScrollPane optionsTab = new JScrollPane(optionsPane, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
                callbacks.customizeUiComponent(optionsTab);
                extensionTabbedPane.addTab("Options", optionsTab);
                // extensionTabbedPane actions
                //extensionTabbedPane.addChangeListener(new ChangeListener() {
                //
                //    @Override
                //    public void stateChanged(ChangeEvent arg0) {
                //        optionsPane.setPreferredSize(new Dimension(50, optionsPaneHeight.getHeight()));
                //        // stdout.println(extensionTabbedPane.getSelectedIndex());
                //    }
                //});

                // miscellaneous initializations
                // hijackModel = new DefaultListModel<>();
                hijackModel = new ArrayList<>();
                // add the custom tab to Burp's UI
                callbacks.addSuiteTab(BurpExtension.this);
                // get burp frame and tabbed pane handler
                //burpFrame = (JFrame) SwingUtilities.getWindowAncestor(extensionTabbedPane);
                burpTabbedPane = (JTabbedPane) extensionTabbedPane.getParent();
                // obtain extension Tab Label control
                // extensionTabLabel = null;
                extensionTabLabel = new JLabel(getTabCaption());
                callbacks.customizeUiComponent(extensionTabLabel);
                // extensionTabLabelRestore = null;
                // extensionTabLabelControl();
                // initial blink
                // extensionTabHighlightOrange();
                // extension state listener
                callbacks.registerExtensionStateListener(BurpExtension.this);
                // stdout.println("Loaded.");
                optionsPane.requestFocus();
                //
                // Load
                // optionsSettingsPersistencyStatus("init");
                optionsSettingsPersistencyLoad();
                // TODO end main
            }
        });
    }

    //
    // implement ITab
    //
    @Override
    public String getTabCaption() {
        return extensionName();
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
        while (!dialogs.isEmpty()) {
            dialogs.get(0).dispose();
        }
        if (extensionTabHighlightTimer != null) {
            try {
                extensionTabHighlightTimer.stop();
                extensionTabHighlightTimer = null;
            } catch (Exception ex) {
                //
            }
        }
        if (hijackTimer != null) {
            try {
                hijackTimer.stop();
                hijackTimer = null;
            } catch (Exception ex) {
                //
            }
        }
    }

    //
    // TODO misc
    //
    byte[] streamToBytes(InputStream in) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        while (true) {
            int r = -1;
            try {
                r = in.read(buffer);
            } catch (IOException ex) {
                //
            }
            if (r == -1) {
                break;
            }
            out.write(buffer, 0, r);
        }
        return out.toByteArray();
    }

    String extensionName() {
        if (optionsSettingsShortenTab.isSelected()) {
            return "*";
        } else {
            return "Wildcard";
        }
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

    /*private void optionsSettingsPersistencyStatus(String moment) {
		callbacks.issueAlert(moment);
		callbacks.issueAlert("optionsSettingsUnsupported = " + String.valueOf(callbacks.loadExtensionSetting("optionsSettingsUnsupported")));
		callbacks.issueAlert("optionsSettingsShortenTab = " + String.valueOf(callbacks.loadExtensionSetting("optionsSettingsShortenTab")));
		callbacks.issueAlert("optionsSettingsHijack = " + String.valueOf(callbacks.loadExtensionSetting("optionsSettingsHijack")));
	}*/
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
        // optionsSettingsPersistencyStatus("save");
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
                // stderr.println(ex);
            } finally {
                if (tabName != null) {
                    boolean regularBurpTab = false;
                    for (String tab : burpTabs) {
                        if (tabName.equals(tab)) {
                            regularBurpTab = true;
                        }
                    }
                    if (!regularBurpTab) {
                        // hijackModel.addElement(tabName);
                        hijackModel.add(tabName);
                    }
                }
            }
        }
        for (int i = 0; i < hijackModel.size(); i++) {
            // String tabName = hijackModel.getElementAt(i);
            String tabName = hijackModel.get(i);
            for (int j = 0; j < burpTabbedPane.getTabCount(); j++) {
                String burpTabName = null;
                try {
                    burpTabName = burpTabbedPane.getTitleAt(j);
                } catch (Exception ex) {
                    // stderr.println(ex);
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
            // String tabName = hijackModel.getElementAt(i);
            String tabName = hijackModel.get(i);
            for (int j = 0; j < extensionTabbedPane.getTabCount(); j++) {
                String extensionTabName = null;
                try {
                    extensionTabName = extensionTabbedPane.getTitleAt(j);
                } catch (Exception ex) {
                    // stderr.println(ex);
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
                hijackTimer = new Timer(1000, new ActionListener() {

                    @Override
                    public void actionPerformed(ActionEvent e) {

                        // get list of new Burp UI tabs
                        boolean unhandledTabs = false;
                        for (int i = 0; i < burpTabbedPane.getTabCount(); i++) {
                            String tabName = null;
                            try {
                                tabName = burpTabbedPane.getTitleAt(i);
                            } catch (Exception ex) {
                                // stderr.println(ex);
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
        extensionTabLabel.setText(extensionName());
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
                // extensionTabIndex = i;
                // stderr.println(ex);
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
        // extensionTabLabel = null;
        // extensionTabLabelRestore = null;
    }

    // extension tab orange label blink
    private void extensionTabHighlightOrange() {
        if (extensionTabHighlightTimer != null) {
            try {
                extensionTabHighlightTimer.stop();
            } catch (Exception ex) {
                //
            }
        }
        extensionTabHighlightTimer = new Timer(4000, new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent e) {
                extensionTabLabel.setForeground(Color.black);
                extensionTabHighlightTimer = null;
            }
        });
        extensionTabLabel.setForeground(new Color(229, 137, 0));
        extensionTabHighlightTimer.setRepeats(false);
        extensionTabHighlightTimer.start();
    }

    //
    // HelperView
    //
    //public class HelperView extends JDialog {
    //
    //    @Override
    //    public void dispose() {
    //        if (dialogs.contains(this)) {
    //            dialogs.remove(this);
    //        }
    //        super.dispose();
    //    }
    //
    //    private JTextArea textArea;
    //
    //    public HelperView(final Component parent, String title, final String filename, String content) {
    //        setTitle(title);
    //        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
    //        setBounds(100, 100, 850, 800);
    //        JMenuBar menu = new JMenuBar();
    //        // callbacks.customizeUiComponent(menuBar);
    //        setJMenuBar(menu);
    //        JMenu menuFile = new JMenu("File");
    //        menu.add(menuFile);
    //        JMenuItem menuFileSaveAs = new JMenuItem("Save As...");
    //        menuFile.add(menuFileSaveAs);
    //        menuFileSaveAs.addActionListener(new ActionListener() {
    //
    //            @Override
    //            public void actionPerformed(ActionEvent e) {
    //                JFileChooser fileChooser = new JFileChooser();
    //                fileChooser.setSelectedFile(new File(filename));
    //                if (fileChooser.showSaveDialog(parent) == JFileChooser.APPROVE_OPTION) {
    //                    File file = fileChooser.getSelectedFile();
    //                    PrintWriter writer;
    //                    try {
    //                        writer = new PrintWriter(file);
    //                        writer.print(textArea.getText());
    //                        writer.close();
    //                    } catch (Exception ex) {
    //                        // ex.printStackTrace(stderr);
    //                        // callbacks.issueAlert("failed.");
    //                    }
    //                }
    //            }
    //        });
    //        JMenuItem menuFileClose = new JMenuItem("Close");
    //        menuFile.add(menuFileClose);
    //        menuFileClose.addActionListener(new ActionListener() {
    //
    //            @Override
    //            public void actionPerformed(ActionEvent e) {
    //                dispose();
    //            }
    //        });
    //        JScrollPane scrollPane = new JScrollPane();
    //        setContentPane(scrollPane);
    //        textArea = new JTextArea();
    //        textArea.setBorder(BorderFactory.createEmptyBorder(2, 5, 2, 5));
    //        callbacks.customizeUiComponent(textArea);
    //        textArea.setFont(new Font("monospaced", Font.PLAIN, 11));
    //        textArea.setText(content);
    //        textArea.setCaretPosition(0);
    //        textArea.setEditable(false);
    //        scrollPane.setViewportView(textArea);
    //        // contentPane.add(textArea, BorderLayout.CENTER);
    //        // setContentPane(textArea);
    //        dialogs.add(this);
    //        setLocationRelativeTo(parent);
    //        setVisible(true);
    //    }
    //}

}
