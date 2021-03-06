resource "aws_s3_bucket" "main" {
  bucket              = "${var.env}-${var.name}"
  region              = "${var.aws_region}"
  acl                 = "private"
  acceleration_status = "Enabled"
}

resource "aws_cloudfront_origin_access_identity" "main" {
  comment = "${var.env} ${var.name} S3 website origin access policy"
}

data "aws_iam_policy_document" "s3" {
  statement {
    actions   = [
      "s3:ListBucket",
      "s3:GetObject"
    ]
    resources = [
      "${aws_s3_bucket.main.arn}",
      "${aws_s3_bucket.main.arn}/*"
    ]
    principals = {
      type = "AWS"
      identifiers = ["${aws_cloudfront_origin_access_identity.main.iam_arn}"]
    }
  }
}

resource "aws_s3_bucket_policy" "main" {
  bucket = "${aws_s3_bucket.main.id}"
  policy = "${data.aws_iam_policy_document.s3.json}"
}





