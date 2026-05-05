#version 450

layout(location = 0) out vec2 vUV;

// Fullscreen-triangle trick: 3 vertices generate a triangle larger than the
// viewport so its rasterized fragments cover the entire screen exactly once.
// No vertex buffer needed — just vkCmdDraw(cmd, 3, 1, 0, 0).
//
// Vertex 0: (-1,-1) UV (0,0)
// Vertex 1: ( 3,-1) UV (2,0)
// Vertex 2: (-1, 3) UV (0,2)
void main() {
    vUV = vec2(float((gl_VertexIndex << 1) & 2), float(gl_VertexIndex & 2));
    gl_Position = vec4(vUV * 2.0 - 1.0, 0.0, 1.0);
}
