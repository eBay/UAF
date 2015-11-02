/*
 * Copyright 2015 eBay Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.ebayopensource.fidouafclient;

import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.text.Editable;
import android.text.TextWatcher;
import android.text.format.DateFormat;
import android.util.Log;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

public class SaveMessageDialog {
	private static final String TAG = SaveMessageDialog.class.getName();

	private static String getFilename(Context context) {
		CharSequence datetime = DateFormat.format("yyyyMMddHHmmss", System.currentTimeMillis());

		return context.getString(R.string.format_message_filename, datetime);
	}

	private static void saveMessage(Context context, CharSequence message, CharSequence filename) {
		File directory = context.getExternalFilesDir(null);

		if (directory == null) {
			Toast.makeText(context, R.string.external_storage_is_unavailable, Toast.LENGTH_SHORT).show();

			return;
		}

		File savedFile = new File(directory, filename.toString());

		BufferedWriter writer = null;
		try {
			writer = new BufferedWriter(new FileWriter(savedFile));
			writer.write(message.toString());

			Toast.makeText(context,
					context.getString(R.string.format_file_is_saved_to, savedFile.getAbsolutePath()),
					Toast.LENGTH_LONG).show();
		} catch (IOException e) {
			Toast.makeText(context, R.string.file_could_not_be_saved, Toast.LENGTH_SHORT).show();
			Log.w(TAG, context.getString(R.string.file_could_not_be_saved), e);
		} finally {
			if (writer != null) {
				try {
					writer.close();
				} catch (IOException e) {
					Toast.makeText(context, R.string.file_could_not_be_saved, Toast.LENGTH_SHORT).show();
					Log.w(TAG, context.getString(R.string.file_could_not_be_saved), e);
				}
			}
		}
	}

	public static void show(final Context context, final TextView messageTextView) {
		final View dialogView = View.inflate(context, R.layout.dialog_save_message, null);
		final EditText filenameEditText = (EditText)dialogView.findViewById(R.id.editFilename);

		final AlertDialog dialog = new AlertDialog.Builder(context).setView(dialogView)
				.setTitle(R.string.enter_message_filename)
				.setPositiveButton(R.string.save, new DialogInterface.OnClickListener() {
					@Override
					public void onClick(DialogInterface dialog, int which) {
						saveMessage(context, messageTextView.getText(), filenameEditText.getText());
					}
				})
				.setNegativeButton(R.string.cancel, new DialogInterface.OnClickListener() {
					@Override
					public void onClick(DialogInterface dialog, int which) {
						dialog.cancel();
					}
				}).create();

		String filename = getFilename(context);

		filenameEditText.setText(filename);
		filenameEditText.addTextChangedListener(new TextWatcher() {
			@Override
			public void beforeTextChanged(CharSequence s, int start, int count, int after) {
				// Nothing to do.
			}

			@Override
			public void onTextChanged(CharSequence s, int start, int before, int count) {
				// Nothing to do.
			}

			@Override
			public void afterTextChanged(Editable s) {
				dialog.getButton(DialogInterface.BUTTON_POSITIVE).setEnabled(0 < s.length());
			}
		});

		dialog.show();
	}
}
