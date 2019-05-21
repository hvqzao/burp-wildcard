// Wildcard Burp Extension, (c) 2015-2019 Marcin Woloszyn (@hvqzao), Released under MIT license
package hvqzao.wildcard;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import java.awt.Dimension;
import java.io.PrintWriter;
import javax.swing.BorderFactory;
import javax.swing.ImageIcon;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JTabbedPane;
import javax.swing.ScrollPaneConstants;
import javax.swing.SpringLayout;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;

public class WildcardExtension implements IBurpExtender {

    private static IBurpExtenderCallbacks callbacks;
    //private static IExtensionHelpers helpers;
    WildcardOptionsPane wildcardOptionsPane;
    private JTabbedPane extensionTabbedPane;
    private static ImageIcon iconHelp;
    private static ImageIcon iconDefaults;
    private static Dimension iconDimension;
    private static PrintWriter stderr;
    private JSeparator separator;
    private JPanel optionsPane;
    private SpringLayout optionsLayout;
    private JPanel previousPane;
    
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        
        WildcardExtension.callbacks = callbacks;
        //helpers = callbacks.getHelpers();

        // set extension name
        callbacks.setExtensionName("Wildcard");
        // draw UI
        SwingUtilities.invokeLater(() -> {
            // abort and exit on dark theme
            if ("nimbus".equals(UIManager.getLookAndFeel().getName().toLowerCase()) == false) {
                new PrintWriter(callbacks.getStdout(), true).println("Other themes than Nimbus are not compatible with this extension. Exiting.");
                callbacks.unloadExtension();
                return;
            }
            stderr = new PrintWriter(callbacks.getStderr(), true);
            // images
            iconHelp = new ImageIcon(new ImageIcon(getClass().getResource("/hvqzao/wildcard/resources/panel_help.png")).getImage().getScaledInstance(13, 13, java.awt.Image.SCALE_SMOOTH));
            iconDefaults = new ImageIcon(new ImageIcon(getClass().getResource("/hvqzao/wildcard/resources/panel_defaults.png")).getImage().getScaledInstance(13, 13, java.awt.Image.SCALE_SMOOTH));
            iconDimension = new Dimension(24, 24);
            // options tab
            extensionTabbedPane = new DnDTabbedPane();
            callbacks.customizeUiComponent(extensionTabbedPane);
            optionsPane = new JPanel();
            optionsPane.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
            optionsLayout = new SpringLayout();
            optionsPane.setLayout(optionsLayout);
            // wildcard options pane
            wildcardOptionsPane = new WildcardOptionsPane(extensionTabbedPane);
            optionsPane.add(wildcardOptionsPane);
            optionsLayout.putConstraint(SpringLayout.NORTH, wildcardOptionsPane, 0, SpringLayout.NORTH, optionsPane);
            previousPane = wildcardOptionsPane;
            // outscope pane
            addSeparator();
            OutscopePane outscopePane = new OutscopePane();
            optionsPane.add(outscopePane);
            optionsLayout.putConstraint(SpringLayout.NORTH, outscopePane, 20, SpringLayout.SOUTH, wildcardOptionsPane);
            //optionsPane.add(Box.createVerticalGlue());
            // [...]
            // next pane
            //addPane(new NextPane());
            // wrap in scrollPane and add as "Options" tab
            JScrollPane optionsTab = new JScrollPane(optionsPane, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
            callbacks.customizeUiComponent(optionsTab);
            extensionTabbedPane.addTab("Options", optionsTab);
            // add extension tab and activate wildcard core functionalities
            wildcardOptionsPane.start();
        });
    }

    public static IBurpExtenderCallbacks getCallbacks() {
        return callbacks;
    }

    public static PrintWriter getStderr() {
        return stderr;
    }

    public static ImageIcon getIconHelp() {
        return iconHelp;
    }

    public static ImageIcon getIconDefaults() {
        return iconDefaults;
    }

    public static Dimension getIconDimension() {
        return iconDimension;
    }

    private void addSeparator() {
        separator = new JSeparator();
        optionsPane.add(separator);
        optionsLayout.putConstraint(SpringLayout.NORTH, separator, 10, SpringLayout.SOUTH, previousPane);
        optionsLayout.putConstraint(SpringLayout.WEST, separator, 0, SpringLayout.WEST, optionsPane);
        optionsLayout.putConstraint(SpringLayout.EAST, separator, 0, SpringLayout.EAST, optionsPane);
    }

    private void addPane(JPanel nextPane) {
        addSeparator();
        optionsPane.add(nextPane);
        optionsLayout.putConstraint(SpringLayout.NORTH, nextPane, 20, SpringLayout.SOUTH, wildcardOptionsPane);
    }

}
