#ifndef QUILL_THEME_H
#define QUILL_THEME_H

#include "imgui.h"

namespace Theme {

namespace C {
    constexpr ImVec4 BG_BASE     = {0.051f, 0.067f, 0.090f, 1.0f};
    constexpr ImVec4 BG_SURFACE  = {0.086f, 0.106f, 0.133f, 1.0f};
    constexpr ImVec4 BG_ELEVATED = {0.114f, 0.141f, 0.173f, 1.0f};
    constexpr ImVec4 BORDER      = {0.129f, 0.149f, 0.180f, 1.0f};
    constexpr ImVec4 BORDER_EM   = {0.188f, 0.212f, 0.251f, 1.0f};
    constexpr ImVec4 ACCENT      = {0.122f, 0.435f, 0.918f, 1.0f};
    constexpr ImVec4 ACCENT_HOVER= {0.216f, 0.522f, 1.000f, 1.0f};
    constexpr ImVec4 ACCENT_DIM  = {0.122f, 0.227f, 0.361f, 1.0f};
    constexpr ImVec4 TEXT_PRI    = {0.788f, 0.820f, 0.851f, 1.0f};
    constexpr ImVec4 TEXT_SEC    = {0.545f, 0.580f, 0.620f, 1.0f};
    constexpr ImVec4 TEXT_DIM    = {0.282f, 0.310f, 0.345f, 1.0f};
    constexpr ImVec4 GREEN       = {0.247f, 0.725f, 0.314f, 1.0f};
    constexpr ImVec4 RED         = {0.973f, 0.318f, 0.286f, 1.0f};
    constexpr ImVec4 YELLOW      = {0.922f, 0.788f, 0.341f, 1.0f};
    constexpr ImVec4 BLUE_TEXT   = {0.345f, 0.651f, 1.000f, 1.0f};
}

inline void Apply() {
    ImGuiStyle& s = ImGui::GetStyle();

    s.WindowRounding    = 8.0f;
    s.ChildRounding     = 6.0f;
    s.FrameRounding     = 5.0f;
    s.PopupRounding     = 5.0f;
    s.ScrollbarRounding = 4.0f;
    s.GrabRounding      = 4.0f;
    s.TabRounding       = 4.0f;

    s.WindowPadding     = {12.0f, 10.0f};
    s.FramePadding      = {10.0f,  6.0f};
    s.ItemSpacing       = { 8.0f,  6.0f};
    s.ItemInnerSpacing  = { 6.0f,  4.0f};
    s.ScrollbarSize     = 10.0f;
    s.GrabMinSize       = 8.0f;
    s.WindowBorderSize  = 1.0f;
    s.ChildBorderSize   = 1.0f;
    s.FrameBorderSize   = 0.0f;
    s.TabBorderSize     = 0.0f;

    ImVec4* col = ImGui::GetStyle().Colors;

    col[ImGuiCol_WindowBg]             = C::BG_BASE;
    col[ImGuiCol_ChildBg]              = C::BG_SURFACE;
    col[ImGuiCol_PopupBg]              = C::BG_ELEVATED;

    col[ImGuiCol_Border]               = C::BORDER;
    col[ImGuiCol_BorderShadow]         = {0,0,0,0};

    col[ImGuiCol_FrameBg]              = C::BG_SURFACE;
    col[ImGuiCol_FrameBgHovered]       = C::BG_ELEVATED;
    col[ImGuiCol_FrameBgActive]        = C::ACCENT_DIM;

    col[ImGuiCol_TitleBg]              = C::BG_BASE;
    col[ImGuiCol_TitleBgActive]        = C::BG_SURFACE;
    col[ImGuiCol_TitleBgCollapsed]     = C::BG_BASE;
    col[ImGuiCol_MenuBarBg]            = C::BG_SURFACE;

    col[ImGuiCol_ScrollbarBg]          = C::BG_BASE;
    col[ImGuiCol_ScrollbarGrab]        = C::BORDER_EM;
    col[ImGuiCol_ScrollbarGrabHovered] = C::TEXT_DIM;
    col[ImGuiCol_ScrollbarGrabActive]  = C::TEXT_SEC;

    col[ImGuiCol_CheckMark]            = C::ACCENT;
    col[ImGuiCol_SliderGrab]           = C::ACCENT;
    col[ImGuiCol_SliderGrabActive]     = C::ACCENT_HOVER;

    col[ImGuiCol_Button]               = C::BG_ELEVATED;
    col[ImGuiCol_ButtonHovered]        = C::ACCENT_DIM;
    col[ImGuiCol_ButtonActive]         = C::ACCENT;

    col[ImGuiCol_Header]               = C::ACCENT_DIM;
    col[ImGuiCol_HeaderHovered]        = C::ACCENT_DIM;
    col[ImGuiCol_HeaderActive]         = C::ACCENT;

    col[ImGuiCol_Separator]            = C::BORDER;
    col[ImGuiCol_SeparatorHovered]     = C::BORDER_EM;
    col[ImGuiCol_SeparatorActive]      = C::ACCENT;

    col[ImGuiCol_ResizeGrip]           = C::BORDER;
    col[ImGuiCol_ResizeGripHovered]    = C::ACCENT_DIM;
    col[ImGuiCol_ResizeGripActive]     = C::ACCENT;

    col[ImGuiCol_Tab]                  = C::BG_SURFACE;
    col[ImGuiCol_TabHovered]           = C::ACCENT_DIM;
    col[ImGuiCol_TabActive]            = C::ACCENT_DIM;
    col[ImGuiCol_TabUnfocused]         = C::BG_SURFACE;
    col[ImGuiCol_TabUnfocusedActive]   = C::BG_ELEVATED;

    col[ImGuiCol_PlotLines]            = C::ACCENT;
    col[ImGuiCol_PlotLinesHovered]     = C::ACCENT_HOVER;
    col[ImGuiCol_PlotHistogram]        = C::ACCENT;
    col[ImGuiCol_PlotHistogramHovered] = C::ACCENT_HOVER;

    col[ImGuiCol_TableHeaderBg]        = C::BG_SURFACE;
    col[ImGuiCol_TableBorderStrong]    = C::BORDER;
    col[ImGuiCol_TableBorderLight]     = C::BORDER;

    col[ImGuiCol_TextSelectedBg]       = C::ACCENT_DIM;
    col[ImGuiCol_DragDropTarget]       = C::ACCENT;
    col[ImGuiCol_NavHighlight]         = C::ACCENT;

    col[ImGuiCol_Text]                 = C::TEXT_PRI;
    col[ImGuiCol_TextDisabled]         = C::TEXT_DIM;
}

inline ImVec4 accent()    { return C::ACCENT;     }
inline ImVec4 green()     { return C::GREEN;      }
inline ImVec4 red()       { return C::RED;        }
inline ImVec4 yellow()    { return C::YELLOW;     }
inline ImVec4 blue_text() { return C::BLUE_TEXT;  }
inline ImVec4 dim()       { return C::TEXT_DIM;   }
inline ImVec4 secondary() { return C::TEXT_SEC;   }
inline ImVec4 primary()   { return C::TEXT_PRI;   }

} // namespace Theme
#endif //QUILL_THEME_H
