import matplotlib.pyplot as plt
import networkx as nx
import PIL
import threading
# Global variable to store the nodes to add crosses
nodes_to_add_cross = []
# Generate the computer network graph
G = nx.Graph()
fig, ax = plt.subplots()
# Transform from data coordinates (scaled between xlim and ylim) to display coordinates
tr_figure = ax.transData.transform
# Transform from display to figure coordinates
tr_axes = fig.transFigure.inverted().transform
pos = nx.multipartite_layout(G, subset_key="layer", align="horizontal")
# Function to receive input and add crosses to nodes
def receive_input():
    global nodes_to_add_cross
    while True:
        # Receive input from the terminal
        node = input("Enter a node number to add a cross (or 'q' to quit): ")
        if node == "q":
            break
        else:
            # Add the node to the list of nodes to add crosses
            nodes_to_add_cross.append(node)
# Function to draw crosses on the graph
def draw_crosses():
    global tr_figure, tr_axes, pos, icon_center, icon_size
    while True:
        if nodes_to_add_cross:
            node = nodes_to_add_cross.pop(0)
            if node in G.nodes:
                xf, yf = tr_figure(pos[node])
                xa, ya = tr_axes((xf, yf))
                # Plot a red cross at the node```python
                a = plt.axes([xa - icon_center, ya - icon_center, icon_size, icon_size])
                a.plot([xa - icon_center, xa + icon_center], [ya - icon_center, ya + icon_center], color='red')
                a.plot([xa - icon_center, xa + icon_center], [ya + icon_center, ya - icon_center], color='red')
                a.axis("off")
                plt.draw()

def addGraph(icons):
    global G, pos, icon_center, icon_size
    edge_labels=0
    # Load images
    images = {k: PIL.Image.open(fname) for k, fname in icons.items()}
    G.add_node("switch_9", image=images["switch"], layer=3)
    G.add_node("switch_10", image=images["switch"], layer=3)
    for i in range(4, 8):
        G.add_node(f"switch_{i}", image=images["switch"], layer=2)

    for u in range(4, 8):
        G.add_edge("switch_9", "switch_" + str(u),label="link_" + str(edge_labels))
        edge_labels+=1
    for u in range(4, 8):
        G.add_edge("switch_10", "switch_" + str(u),label="link_" + str(edge_labels))
        edge_labels+=1

    serverNum=0
    for i in range(0, 4):
        G.add_node(f"switch_{i}", image=images["switch"], layer=1)
        for j in range(0, 2):
            G.add_node("server_" + str(serverNum), image=images["server"], layer=0)
            serverNum+=1


    for u in range(4, 6):
        for v in range(0,2):
            G.add_edge("switch_" + str(u), "switch_" + str(v),label="link_" + str(edge_labels))
            edge_labels+=1
    for u in range(6, 8):
        for v in range(2,4):
            G.add_edge("switch_" + str(u), "switch_" + str(v),label="link_" + str(edge_labels))
            edge_labels+=1
    serverNum=0
    for u in range(0, 4):
        for v in range(0,2):
            G.add_edge("switch_" + str(u), "server_" + str(serverNum),label="link_" + str(edge_labels))
            edge_labels+=1
            serverNum+=1
def paint():
    global G,pos,tr_figure, tr_axes
    # Image URLs for graph nodes
    icons = {
        "server": "icons/server.png",
        "switch": "icons/switch.png",
    }
    addGraph(icons)

    # Get a reproducible layout and create figure
    pos = nx.multipartite_layout(G, subset_key="layer", align="horizontal")

    # Note: the min_source/target_margin kwargs only work with FancyArrowPatch objects.
    # Force the use of FancyArrowPatch for edge drawing by setting `arrows=True`,
    # but suppress arrowheads with `arrowstyle="-"`
    nx.draw_networkx_edges(
        G,
        pos=pos,
        ax=ax,
        arrows=True,
        arrowstyle="-",
        min_source_margin=15,
        min_target_margin=15,
    )


    # Select the size of the image (relative to the X axis)
    icon_size = (ax.get_xlim()[1] - ax.get_xlim()[0]) * 0.025
    icon_center = icon_size / 2.0

    # Add the respective image to each node
    for n in G.nodes:
        xf, yf = tr_figure(pos[n])
        xa, ya = tr_axes((xf, yf))
        # get overlapped axes and plot icon
        a = plt.axes([xa - icon_center, ya - icon_center, icon_size, icon_size])
        a.imshow(G.nodes[n]["image"])
        a.axis("off")

    # Add labels to the nodes
    labels = {n: n for n in G.nodes}
    label_pos = {n: (pos[n][0]- 3*icon_center, pos[n][1] + 2*icon_center) for n in G.nodes}  # Adjust label position
    nx.draw_networkx_labels(G, label_pos, labels=labels, ax=ax, verticalalignment="top")




    # Start the thread to receive input
    input_thread = threading.Thread(target=receive_input)
    input_thread.start()


    # Start the thread to draw crosses
    crosses_thread = threading.Thread(target=draw_crosses)
    crosses_thread.start()

    # Show the plot
    plt.show()

    # Wait for the input thread to finish
    input_thread.join()

paint()