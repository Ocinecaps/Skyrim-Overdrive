#version 450

layout(location = 0) in vec2 vUV;
layout(location = 0) out vec4 fColor;

layout(set = 0, binding = 0) uniform sampler2D uTex;

void main() {
    fColor = texture(uTex, vUV);
}
