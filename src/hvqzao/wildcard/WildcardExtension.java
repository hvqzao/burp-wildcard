// Wildcard Burp Extension, (c) 2015-2017 Marcin Woloszyn (@hvqzao), Released under MIT license
package hvqzao.wildcard;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import java.awt.Dimension;
import java.io.PrintWriter;
import javax.swing.BoxLayout;
import javax.swing.ImageIcon;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingUtilities;

public class WildcardExtension implements IBurpExtender {

    private static IBurpExtenderCallbacks callbacks;
    //private static IExtensionHelpers helpers;
    WildcardOptionsPane wildcardOptionsPane;
    private JTabbedPane extensionTabbedPane;
    private static ImageIcon iconHelp;
    private static ImageIcon iconDefaults;
    private static Dimension iconDimension;
    private static PrintWriter stderr;
        
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        WildcardExtension.callbacks = callbacks;
        //helpers = callbacks.getHelpers();
        stderr = new PrintWriter(callbacks.getStderr(), true);
        // set extension name
        callbacks.setExtensionName("Wildcard");
        // draw UI
        SwingUtilities.invokeLater(() -> {
            try {
                // images
                iconHelp = new ImageIcon(new ImageIcon(getClass().getResource("/hvqzao/wildcard/resources/panel_help.png")).getImage().getScaledInstance(13, 13, java.awt.Image.SCALE_SMOOTH));
                iconDefaults = new ImageIcon(new ImageIcon(getClass().getResource("/hvqzao/wildcard/resources/panel_defaults.png")).getImage().getScaledInstance(13, 13, java.awt.Image.SCALE_SMOOTH));
                iconDimension = new Dimension(24, 24);

                // options tab
                extensionTabbedPane = new DnDTabbedPane();
                callbacks.customizeUiComponent(extensionTabbedPane);
                JPanel optionsPane = new JPanel();
                // Y_AXIS BoxLayout
                optionsPane.setLayout(new BoxLayout(optionsPane, BoxLayout.Y_AXIS));
                // wildcard options pane
                wildcardOptionsPane = new WildcardOptionsPane(extensionTabbedPane);
                optionsPane.add(wildcardOptionsPane);
                // wrap in scrollPane and add as "Options" tab
                JScrollPane optionsTab = new JScrollPane(optionsPane, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
                callbacks.customizeUiComponent(optionsTab);
                extensionTabbedPane.addTab("Options", optionsTab);

                // add extension tab and activate wildcard core functionalities
                wildcardOptionsPane.start();
            } catch (Exception ex) {
                ex.printStackTrace(stderr);
            }
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
}
