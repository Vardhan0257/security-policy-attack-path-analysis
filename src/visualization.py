import plotly.graph_objects as go
import networkx as nx


def visualize_graph(graph, attack_paths=None, output_file="graph_visualization.html"):
    """
    Visualize the security graph with optional highlighting of attack paths.

    Args:
        graph: NetworkX DiGraph
        attack_paths: List of paths to highlight (optional)
        output_file: Output HTML file name
    """
    # Create positions for nodes
    pos = nx.spring_layout(graph, seed=42)

    # Prepare node data
    node_x = []
    node_y = []
    node_text = []
    node_color = []

    for node in graph.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        node_text.append(f"{node}<br>Type: {graph.nodes[node].get('type', 'unknown')}")
        # Color nodes: red for critical, blue for others
        if graph.nodes[node].get('criticality') == 'high':
            node_color.append('red')
        else:
            node_color.append('lightblue')

    # Prepare edge data
    edge_x = []
    edge_y = []
    edge_text = []

    for edge in graph.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])
        edge_type = graph.edges[edge].get('type', 'unknown')
        edge_text.append(f"{edge[0]} -> {edge[1]}<br>Type: {edge_type}")

    # Highlight attack paths if provided
    highlight_edge_x = []
    highlight_edge_y = []
    if attack_paths:
        for path in attack_paths:
            for i in range(len(path) - 1):
                x0, y0 = pos[path[i]]
                x1, y1 = pos[path[i + 1]]
                highlight_edge_x.extend([x0, x1, None])
                highlight_edge_y.extend([y0, y1, None])

    # Create figure
    fig = go.Figure()

    # Add edges
    fig.add_trace(go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=0.5, color='#888'),
        hoverinfo='text',
        text=edge_text,
        mode='lines',
        name='Edges'
    ))

    # Add highlighted paths
    if attack_paths:
        fig.add_trace(go.Scatter(
            x=highlight_edge_x, y=highlight_edge_y,
            line=dict(width=3, color='red'),
            hoverinfo='text',
            mode='lines',
            name='Attack Paths'
        ))

    # Add nodes
    fig.add_trace(go.Scatter(
        x=node_x, y=node_y,
        mode='markers+text',
        text=[node for node in graph.nodes()],
        textposition="top center",
        hoverinfo='text',
        textfont=dict(size=10),
        marker=dict(
            size=20,
            color=node_color,
            line_width=2
        ),
        name='Nodes'
    ))

    # Update layout
    fig.update_layout(
        title="Security Policy Attack Path Graph",
        showlegend=True,
        hovermode='closest',
        margin=dict(b=20, l=5, r=5, t=40),
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
    )

    # Save to HTML
    fig.write_html(output_file)
    print(f"Visualization saved to {output_file}")