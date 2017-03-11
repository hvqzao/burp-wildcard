package hvqzao.wildcard;

public class Unused {

    //private final ArrayList<JDialog> dialogs = new ArrayList<>();
    //private JFrame burpFrame;
    //
    private void initialize() {
        //SwingUtilities.invokeLater(() -> {
        ////...
        //final JLabel optionsSettingsTitle = new JLabel("<html><b style='color:#e58900;font-size:10px'>Settings</b></html>");
        //JLabel optionsSettingsDescription = new JLabel("<html>Use these settings to control extension behavior.</html>");
        ////...
        //
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
        //}
    }

    //
    // TODO misc
    //
    //byte[] streamToBytes(InputStream in) {
    //    ByteArrayOutputStream out = new ByteArrayOutputStream();
    //    byte[] buffer = new byte[1024];
    //    while (true) {
    //        int r = -1;
    //        try {
    //            r = in.read(buffer);
    //        } catch (IOException ex) {
    //            //
    //        }
    //        if (r == -1) {
    //            break;
    //        }
    //        out.write(buffer, 0, r);
    //    }
    //    return out.toByteArray();
    //}
    //
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
    //
    //        // get burp frame and tabbed pane handler
    //        burpFrame = (JFrame) SwingUtilities.getWindowAncestor(extensionTabbedPane);
    //    }
    //}
    //
    // implement IExtensionStateListener
    //
    //@Override
    //public void extensionUnloaded() {
    //    while (!dialogs.isEmpty()) {
    //        dialogs.get(0).dispose();
    //    }
    //}
}
