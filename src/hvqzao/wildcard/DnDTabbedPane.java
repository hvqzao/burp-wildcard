package hvqzao.wildcard;

//http://java-swing-tips.blogspot.com/2008/04/drag-and-drop-tabs-in-jtabbedpane.html
import java.awt.AlphaComposite;
import java.awt.Color;
import java.awt.Component;
import java.awt.EventQueue;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.Point;
import java.awt.Rectangle;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.dnd.DnDConstants;
import java.awt.dnd.DragGestureEvent;
import java.awt.dnd.DragGestureListener;
import java.awt.dnd.DragSource;
import java.awt.dnd.DragSourceDragEvent;
import java.awt.dnd.DragSourceDropEvent;
import java.awt.dnd.DragSourceEvent;
import java.awt.dnd.DragSourceListener;
import java.awt.dnd.DropTarget;
import java.awt.dnd.DropTargetDragEvent;
import java.awt.dnd.DropTargetDropEvent;
import java.awt.dnd.DropTargetEvent;
import java.awt.dnd.DropTargetListener;
import java.awt.dnd.InvalidDnDOperationException;
import java.awt.geom.Rectangle2D;
import java.awt.image.BufferedImage;

import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;

@SuppressWarnings("serial")
public class DnDTabbedPane extends JTabbedPane {

    private static final int LINEWIDTH = 3;
    private static final String NAME = "test";
    private final GhostGlassPane glassPane = new GhostGlassPane();
    private final Rectangle2D lineRect = new Rectangle2D.Double();
    private final Color lineColor = new Color(247, 144, 15); // Color(0, 100, 255);
    // private final DragSource dragSource = new DragSource();
    // private final DropTarget dropTarget;
    private int dragTabIndex = -1;

    public DnDTabbedPane() {
        super();
        final DragSourceListener dsl = new DragSourceListener() {
            @Override
            public void dragEnter(DragSourceDragEvent e) {
                e.getDragSourceContext().setCursor(DragSource.DefaultMoveDrop);
            }

            @Override
            public void dragExit(DragSourceEvent e) {
                e.getDragSourceContext().setCursor(DragSource.DefaultMoveNoDrop);
                lineRect.setRect(0, 0, 0, 0);
                glassPane.setPoint(new Point(-1000, -1000));
                glassPane.repaint();
            }

            @Override
            public void dragOver(DragSourceDragEvent e) {
                // e.getLocation()
                // This method returns a Point indicating the cursor location in screen coordinates at the moment
                Point tabPt = e.getLocation();
                SwingUtilities.convertPointFromScreen(tabPt, DnDTabbedPane.this);
                Point glassPt = e.getLocation();
                SwingUtilities.convertPointFromScreen(glassPt, glassPane);
                int targetIdx = getTargetTabIndex(glassPt);
                if (getTabAreaBound().contains(tabPt) && targetIdx >= 0 && targetIdx != dragTabIndex && targetIdx != dragTabIndex + 1) {
                    e.getDragSourceContext().setCursor(DragSource.DefaultMoveDrop);
                } else {
                    e.getDragSourceContext().setCursor(DragSource.DefaultMoveNoDrop);
                }
            }

            @Override
            public void dragDropEnd(DragSourceDropEvent e) {
                lineRect.setRect(0, 0, 0, 0);
                dragTabIndex = -1;
                if (hasGhost()) {
                    glassPane.setVisible(false);
                    glassPane.setImage(null);
                }
                EventQueue.invokeLater(new Runnable() { // FIXME? added to fix with dark blue tab, sometimes cause awt exception

                    @Override
                    public void run() {
                        updateUI();
                    }

                });
            }

            @Override
            public void dropActionChanged(DragSourceDragEvent e) {

            }
        };
        final Transferable t = new Transferable() {
            private final DataFlavor FLAVOR = new DataFlavor(DataFlavor.javaJVMLocalObjectMimeType, NAME);

            @Override
            public Object getTransferData(DataFlavor flavor) {
                return DnDTabbedPane.this;
            }

            @Override
            public DataFlavor[] getTransferDataFlavors() {
                DataFlavor[] f = new DataFlavor[1];
                f[0] = this.FLAVOR;
                return f;
            }

            @Override
            public boolean isDataFlavorSupported(DataFlavor flavor) {
                return flavor.getHumanPresentableName().equals(NAME);
            }
        };
        final DragGestureListener dgl = new DragGestureListener() {
            @Override
            public void dragGestureRecognized(DragGestureEvent e) {
                Point tabPt = e.getDragOrigin();
                dragTabIndex = indexAtLocation(tabPt.x, tabPt.y);
                if (dragTabIndex < 0) {
                    return;
                }
                initGlassPane(e.getComponent(), e.getDragOrigin());
                try {
                    e.startDrag(DragSource.DefaultMoveDrop, t, dsl);
                } catch (InvalidDnDOperationException idoe) {
                    // idoe.printStackTrace();
                }
            }
        };
        // dropTarget =
        new DropTarget(glassPane, DnDConstants.ACTION_COPY_OR_MOVE, new CDropTargetListener(), true);
        new DragSource().createDefaultDragGestureRecognizer(this, DnDConstants.ACTION_COPY_OR_MOVE, dgl);
    }

    private class CDropTargetListener implements DropTargetListener {

        @Override
        public void dragEnter(DropTargetDragEvent e) {
            if (isDragAcceptable(e)) {
                e.acceptDrag(e.getDropAction());
            } else {
                e.rejectDrag();
            }
        }

        @Override
        public void dragExit(DropTargetEvent e) {
        }

        @Override
        public void dropActionChanged(DropTargetDragEvent e) {
        }

        @Override
        public void dragOver(final DropTargetDragEvent e) {
            if (getTabPlacement() == JTabbedPane.TOP || getTabPlacement() == JTabbedPane.BOTTOM) {
                initTargetLeftRightLine(getTargetTabIndex(e.getLocation()));
            } else {
                initTargetTopBottomLine(getTargetTabIndex(e.getLocation()));
            }
            repaint();
            if (hasGhost()) {
                glassPane.setPoint(e.getLocation());
                glassPane.repaint();
            }
        }

        @Override
        public void drop(DropTargetDropEvent e) {
            if (isDropAcceptable(e)) {
                convertTab(dragTabIndex, getTargetTabIndex(e.getLocation()));
                e.dropComplete(true);
            } else {
                e.dropComplete(false);
            }
            repaint();
        }

        public boolean isDragAcceptable(DropTargetDragEvent e) {
            Transferable t = e.getTransferable();
            if (t == null) {
                return false;
            }
            DataFlavor[] f = e.getCurrentDataFlavors();
            if (t.isDataFlavorSupported(f[0]) && dragTabIndex >= 0) {
                return true;
            }
            return false;
        }

        public boolean isDropAcceptable(DropTargetDropEvent e) {
            Transferable t = e.getTransferable();
            if (t == null) {
                return false;
            }
            DataFlavor[] f = t.getTransferDataFlavors();
            if (t.isDataFlavorSupported(f[0]) && dragTabIndex >= 0) {
                return true;
            }
            return false;
        }
    }

    private boolean hasGhost = true;

    public void setPaintGhost(boolean flag) {
        hasGhost = flag;
    }

    public boolean hasGhost() {
        return hasGhost;
    }

    private int getTargetTabIndex(Point glassPt) {
        Point tabPt = SwingUtilities.convertPoint(glassPane, glassPt, DnDTabbedPane.this);
        boolean isTB = getTabPlacement() == JTabbedPane.TOP || getTabPlacement() == JTabbedPane.BOTTOM;
        for (int i = 0; i < getTabCount(); i++) {
            Rectangle r = getBoundsAt(i);
            if (isTB) {
                r.setRect(r.x - r.width / 2, r.y, r.width, r.height);
            } else {
                r.setRect(r.x, r.y - r.height / 2, r.width, r.height);
            }
            if (r.contains(tabPt)) {
                return i;
            }
        }
        Rectangle r = getBoundsAt(getTabCount() - 1);
        if (isTB) {
            r.setRect(r.x + r.width / 2, r.y, r.width, r.height);
        } else {
            r.setRect(r.x, r.y + r.height / 2, r.width, r.height);
        }
        return r.contains(tabPt) ? getTabCount() : -1;
    }

    private void convertTab(int prev, int next) {
        if (next < 0 || prev == next) {
            // System.out.println("press="+prev+" next="+next);
            return;
        }
        Component cmp = getComponentAt(prev);
        String str = getTitleAt(prev);
        if (next == getTabCount()) {
            // System.out.println("last: press="+prev+" next="+next);
            remove(prev);
            addTab(str, cmp);
            setSelectedIndex(getTabCount() - 1);
        } else if (prev > next) {
            // System.out.println("   >: press="+prev+" next="+next);
            remove(prev);
            insertTab(str, null, cmp, null, next);
            setSelectedIndex(next);
        } else {
            // System.out.println("   <: press="+prev+" next="+next);
            remove(prev);
            insertTab(str, null, cmp, null, next - 1);
            setSelectedIndex(next - 1);
        }
    }

    private void initTargetLeftRightLine(int next) {
        if (next < 0 || dragTabIndex == next || next - dragTabIndex == 1) {
            lineRect.setRect(0, 0, 0, 0);
        } else if (next == getTabCount()) {
            Rectangle rect = getBoundsAt(getTabCount() - 1);
            lineRect.setRect(rect.x + rect.width - LINEWIDTH / 2, rect.y, LINEWIDTH, rect.height);
        } else if (next == 0) {
            Rectangle rect = getBoundsAt(0);
            lineRect.setRect(-LINEWIDTH / 2 + 10, rect.y, LINEWIDTH, rect.height);
        } else {
            Rectangle rect = getBoundsAt(next - 1);
            lineRect.setRect(rect.x + rect.width - LINEWIDTH / 2, rect.y, LINEWIDTH, rect.height);
        }
    }

    private void initTargetTopBottomLine(int next) {
        if (next < 0 || dragTabIndex == next || next - dragTabIndex == 1) {
            lineRect.setRect(0, 0, 0, 0);
        } else if (next == getTabCount()) {
            Rectangle rect = getBoundsAt(getTabCount() - 1);
            lineRect.setRect(rect.x, rect.y + rect.height - LINEWIDTH / 2, rect.width, LINEWIDTH);
        } else if (next == 0) {
            Rectangle rect = getBoundsAt(0);
            lineRect.setRect(rect.x + 10, -LINEWIDTH / 2, rect.width, LINEWIDTH);
        } else {
            Rectangle rect = getBoundsAt(next - 1);
            lineRect.setRect(rect.x, rect.y + rect.height - LINEWIDTH / 2, rect.width, LINEWIDTH);
        }
    }

    private void initGlassPane(Component c, Point tabPt) {
        // Point p = (Point) pt.clone();
        getRootPane().setGlassPane(glassPane);
        if (hasGhost()) {
            Rectangle rect = getBoundsAt(dragTabIndex);
            BufferedImage image = new BufferedImage(c.getWidth(), c.getHeight(), BufferedImage.TYPE_INT_ARGB);
            Graphics g = image.getGraphics();
            c.paint(g);
            image = image.getSubimage(rect.x, rect.y, rect.width, rect.height);
            glassPane.setImage(image);
        }
        Point glassPt = SwingUtilities.convertPoint(c, tabPt, glassPane);
        glassPane.setPoint(glassPt);
        glassPane.setVisible(true);
    }

    private Rectangle getTabAreaBound() {
        Rectangle lastTab = getUI().getTabBounds(this, getTabCount() - 1);
        return new Rectangle(0, 0, getWidth(), lastTab.y + lastTab.height);
    }

    @Override
    public void paintComponent(Graphics g) {
        super.paintComponent(g);
        if (dragTabIndex >= 0) {
            Graphics2D g2 = (Graphics2D) g;
            g2.setPaint(lineColor);
            g2.fill(lineRect);
        }
    }

    private class GhostGlassPane extends JPanel {

        private final AlphaComposite composite;
        private Point location = new Point(0, 0);
        private BufferedImage draggingGhost = null;

        public GhostGlassPane() {
            setOpaque(false);
            composite = AlphaComposite.getInstance(AlphaComposite.SRC_OVER, 0.5f);
        }

        public void setImage(BufferedImage draggingGhost) {
            this.draggingGhost = draggingGhost;
        }

        public void setPoint(Point location) {
            this.location = location;
        }

        @Override
        public void paintComponent(Graphics g) {
            if (draggingGhost == null) {
                return;
            }
            Graphics2D g2 = (Graphics2D) g;
            g2.setComposite(composite);
            double xx = location.getX() - (draggingGhost.getWidth(this) / 2d);
            double yy = location.getY() - (draggingGhost.getHeight(this) / 2d);
            g2.drawImage(draggingGhost, (int) xx, (int) yy, null);
        }
    }

}
