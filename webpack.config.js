const webpack = require("webpack");
const path = require("path");
const { BundleAnalyzerPlugin } = require("webpack-bundle-analyzer");
const HtmlWebpackPlugin = require("html-webpack-plugin");
const CopyWebpackPlugin = require("copy-webpack-plugin");
const { SubresourceIntegrityPlugin } = require("webpack-subresource-integrity");

const devMode = process.env.NODE_ENV !== "production";

const plugins = [
  new CopyWebpackPlugin({
    patterns: [
      {
        from: path.resolve(__dirname, "public"),
        to: path.resolve(__dirname, "dist"),
        toType: "dir",
        noErrorOnMissing: true,
        globOptions: {
          ignore: [path.resolve(__dirname, "./public/index.html")],
        },
        info: {
          minimized: true,
        },
      },
    ],
  }),
  new HtmlWebpackPlugin({
    template: path.resolve(__dirname, "./public/index.html"),
    hash: true,
    scriptLoading: "defer",
    inject: "body",
  }),
  new webpack.ProvidePlugin({
    Buffer: ["buffer", "Buffer"],
  }),
  new webpack.ProvidePlugin({
    process: "process/browser.js",
  }),
  new BundleAnalyzerPlugin({
    analyzerMode: "disabled",
    openAnalyzer: false,
  }),
];

if (!devMode) plugins.push(new SubresourceIntegrityPlugin());

/** @type {import("webpack").Configuration} */
module.exports = {
  devServer: {
    port: 8080,
  },
  mode: process.env.NODE_ENV || "production",
  devtool: devMode ? "source-map" : false,
  entry: "./client/browser.ts",
  target: "web",
  output: {
    path: path.resolve(__dirname, "./dist"),
    filename: "bundle.js",
    crossOriginLoading: "anonymous",
  },
  resolve: {
    extensions: [".ts", ".js"],
    alias: {
      "bn.js": path.resolve("./node_modules", "bn.js"),
    },
    fallback: {
      http: require.resolve("stream-http"),
      https: require.resolve("https-browserify"),
      os: require.resolve("os-browserify/browser"),
      crypto: require.resolve("crypto-browserify"),
      assert: require.resolve("assert/"),
      stream: require.resolve("stream-browserify"),
      url: require.resolve("url/"),
      buffer: require.resolve("buffer/"),
      fs: false,
      path: false,
    },
  },
  plugins,
  module: {
    rules: [
      {
        test: /\.css$/,
        use: ["style-loader", "css-loader"],
      },
      {
        test: /\.(ts|js)x?$/,
        exclude: /(node_modules|bower_components)/,
        use: {
          loader: "babel-loader",
          options: {
            cacheDirectory: true,
            cacheCompression: false,
            targets: ["> 0.5%", "not dead", "not ie 11"],
          },
        },
      },
    ],
  },
};
