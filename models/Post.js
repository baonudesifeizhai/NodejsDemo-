const mongoose = require("mongoose");

const PostSchema = new mongoose.Schema(
  {
    username: {
        type: String,
        required: true,
      },
      categories: {
        type: Array,
        required: false,
      },
    title: {
      type: String,
      required: true,
      unique: true,
    },
    desc: {
      type: String,
      required: true,
    },
    photo: {
      type: String,
      required: false,
    },
 
  },
  { timestamps: true }
);

module.exports = mongoose.model("Post", PostSchema);