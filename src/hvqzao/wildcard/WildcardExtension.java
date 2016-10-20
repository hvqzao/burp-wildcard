// Wildcard Burp Extension, (c) 2015-2016 Marcin Woloszyn (@hvqzao), Released under MIT license
package hvqzao.wildcard;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionStateListener;
import burp.ITab;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;

import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingUtilities;
import javax.swing.Timer;

public class WildcardExtension implements IBurpExtender, ITab, IExtensionStateListener {

    private static IBurpExtenderCallbacks callbacks;
    //private static IExtensionHelpers helpers;
    private JTabbedPane extensionTabbedPane;
    private JLabel extensionTabLabel;
    private Component extensionTabLabelRestore;
    private Timer extensionTabHighlightTimer;
    //private JFrame burpFrame;
    private JTabbedPane burpTabbedPane;
    //private DefaultListModel<String> hijackModel;
    private ArrayList<String> hijackModel;
    private JCheckBox optionsSettingsUnsupported;
    private JCheckBox optionsSettingsPersistency;
    private JCheckBox optionsSettingsShortenTab;
    private final String[] defaultBurpTabs = {"Target", "Proxy", "Spider", "Scanner", "Intruder", "Repeater", "Sequencer", "Decoder", "Comparer", "Extender", "Options", "User options", "Project options", "Alerts", "*"};
    private final ArrayList<String> burpTabs = new ArrayList<>();
    private JCheckBox optionsSettingsHijack;
    //private final ArrayList<JDialog> dialogs = new ArrayList<>();
    private Timer hijackTimer;

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        // keep a reference to our callbacks object
        WildcardExtension.callbacks = callbacks;
        //// obtain an extension helpers object
        //helpers = callbacks.getHelpers();
        // set extension name
        callbacks.setExtensionName("Wildcard");
        // draw UI
        SwingUtilities.invokeLater(() -> {
            // images
            ImageIcon iconHelp = new ImageIcon(new ImageIcon(getClass().getResource("/hvqzao/wildcard/resources/panel_help.png")).getImage().getScaledInstance(13, 13, java.awt.Image.SCALE_SMOOTH));
            ImageIcon iconDefaults = new ImageIcon(new ImageIcon(getClass().getResource("/hvqzao/wildcard/resources/panel_defaults.png")).getImage().getScaledInstance(13, 13, java.awt.Image.SCALE_SMOOTH));
            Dimension iconDimension = new Dimension(24, 24);
            // main tab
            //extensionTabbedPane = new JTabbedPane();
            extensionTabbedPane = new DnDTabbedPane();
            callbacks.customizeUiComponent(extensionTabbedPane);

            // options tab
            final WildcardOptionsPane optionsPane = new WildcardOptionsPane();
            // options settings
            JButton optionsSettingsHelp = optionsPane.getOptionsSettingsHelp();
            optionsSettingsHelp.setIcon(iconHelp);
            callbacks.customizeUiComponent(optionsSettingsHelp);
            optionsSettingsHelp.setEnabled(false);
            //
            JButton optionsSettingsDefaults = optionsPane.getOptionsSettingsDefaults();
            optionsSettingsDefaults.setIcon(iconDefaults);
            callbacks.customizeUiComponent(optionsSettingsDefaults);
            //
            //final JLabel optionsSettingsTitle = new JLabel("<html><b style='color:#e58900;font-size:10px'>Settings</b></html>");
            final JLabel optionsSettingsTitle = optionsPane.getOptionsSettingsTitle();
            //
            //JLabel optionsSettingsDescription = new JLabel("<html>Use these settings to control extension behavior.</html>");
            final JLabel optionsSettingsDescription = optionsPane.getOptionsSettingsDescription();
            //
            //optionsSettingsUnsupported = new JCheckBox("Enable features not officially supported by Burp Extender");
            optionsSettingsUnsupported = optionsPane.getOptionsSettingsUnsupported();
            callbacks.customizeUiComponent(optionsSettingsUnsupported);
            //
            //optionsSettingsPersistency = new JCheckBox("Remember those settings (potentially unsafe)");
            optionsSettingsPersistency = optionsPane.getOptionsSettingsPersistency();
            callbacks.customizeUiComponent(optionsSettingsPersistency);
            optionsSettingsPersistency.setEnabled(false);
            //
            //optionsSettingsShortenTab = new JCheckBox("Shorten extension name on main tab");
            optionsSettingsShortenTab = optionsPane.getOptionsSettingsShortenTab();
            optionsSettingsShortenTab.setSelected(true);
            callbacks.customizeUiComponent(optionsSettingsShortenTab);
            optionsSettingsShortenTab.setEnabled(false);
            optionsSettingsShortenTab.addActionListener((ActionEvent e) -> {
                if (optionsSettingsPersistency.isSelected()) {
                    callbacks.saveExtensionSetting("optionsSettingsShortenTab", String.valueOf(optionsSettingsShortenTab.isSelected()));
                }
                optionsSettingsShortenTabUpdate();
                extensionTabHighlightOrange();
            });
            //
            //optionsSettingsHijack = new JCheckBox("Hijack tabs belonging to other extensions");
            optionsSettingsHijack = optionsPane.getOptionsSettingsHijack();
            optionsSettingsHijack.setSelected(true);
            callbacks.customizeUiComponent(optionsSettingsHijack);
            optionsSettingsHijack.setEnabled(false);
            optionsSettingsHijack.addActionListener((ActionEvent e) -> {
                if (optionsSettingsPersistency.isSelected()) {
                    callbacks.saveExtensionSetting("optionsSettingsHijack", String.valueOf(optionsSettingsHijack.isSelected()));
                }
                optionsSettingsHijackUpdate();
            });
            // Helpers
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
            optionsSettingsDefaults.addActionListener((ActionEvent e) -> {
                optionsSettingsUnsupported.setSelected(false);
                optionsSettingsPersistency.setSelected(false);
                optionsSettingsUnsupportedChange();
            });
            // options Unsupported
            optionsSettingsUnsupported.addActionListener((ActionEvent e) -> {
                optionsSettingsUnsupportedChange();
            });
            // options Persistency
            optionsSettingsPersistency.addActionListener((ActionEvent e) -> {
                optionsSettingsPersistencySave();
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
            Arrays.stream(defaultBurpTabs).forEach(e -> burpTabs.add(e));
            //hijackModel = new DefaultListModel<>();
            hijackModel = new ArrayList<>();
            // add the custom tab to Burp's UI
            callbacks.addSuiteTab(WildcardExtension.this);
            // get burp frame and tabbed pane handler
            //burpFrame = (JFrame) SwingUtilities.getWindowAncestor(extensionTabbedPane);
            burpTabbedPane = (JTabbedPane) extensionTabbedPane.getParent();
            // obtain extension Tab Label control
            //extensionTabLabel = null;
            extensionTabLabel = new JLabel(getTabCaption());
            callbacks.customizeUiComponent(extensionTabLabel);
            //extensionTabLabelRestore = null;
            //extensionTabLabelControl();
            // initial blink
            //extensionTabHighlightOrange();
            // extension state listener
            //callbacks.registerExtensionStateListener(WildcardExtension.this);
            //stdout.println("Loaded.");
            optionsPane.requestFocus();
            //
            // Load
            //optionsSettingsPersistencyStatus("init");
            optionsSettingsPersistencyLoad();
            // TODO end main
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
        //while (!dialogs.isEmpty()) {
        //    dialogs.get(0).dispose();
        //}
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
                //extensionTabIndex = i;
                //stderr.println(ex);
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

    ////
    //// HelperView
    ////
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
    //        //contentPane.add(textArea, BorderLayout.CENTER);
    //        //setContentPane(textArea);
    //        dialogs.add(this);
    //        setLocationRelativeTo(parent);
    //        setVisible(true);
    //    }
    //}
}
