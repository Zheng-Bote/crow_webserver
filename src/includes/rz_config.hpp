/**
 * @file config.hpp.in
 * @author ZHENG Robert (robert.hase-zheng.net)
 * @brief configuration
 * @version 2.0.0
 * @date 2025-11-15
 *
 * @copyright Copyright (c) 2025 ZHENG Robert
 *
 */
#pragma once

#include <cstdint>
#include <string>

static const std::string PROJECT_NAME = "CrowQtServer";
static const std::string PROG_LONGNAME = "write Binary formats";
static const std::string PROJECT_DESCRIPTION = "Crow Webserver with Qt6 for photo uploads";

static const std::string PROJECT_EXECUTABLE = "CrowQtServer";

static const std::string PROJECT_VERSION = "0.4.0";
static const std::int32_t PROJECT_VERSION_MAJOR{0};
static const std::int32_t PROJECT_VERSION_MINOR{4};
static const std::int32_t PROJECT_VERSION_PATCH{0};

static const std::string PROJECT_HOMEPAGE_URL = "https://github.com/Zheng-Bote/crow_webserver";
static const std::string PROG_AUTHOR = "ZHENG Bote";
static const std::string PROG_CREATED = "2025";
static const std::string PROG_ORGANIZATION_NAME = "ZHENG Robert";
static const std::string PROG_ORGANIZATION_DOMAIN = "net.hase-zheng";

static const std::string CMAKE_CXX_STANDARD = "c++23";
static const std::string CMAKE_CXX_COMPILER = "GNU 15.2.0";
static const std::string CMAKE_QT_VERSION = "6.9.2";
